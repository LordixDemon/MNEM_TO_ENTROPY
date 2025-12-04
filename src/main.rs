use bip39::{Mnemonic, Language};
use clap::Parser;
use std::str::FromStr;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser, Debug)]
#[command(
    name = "mnem_to_entropy",
    about = "Утилита для конвертации мнемонической фразы обратно в энтропию",
    version = "0.1.0"
)]
struct Args {
    #[arg(short, long)]
    mnemonic: Option<String>,

    #[arg(short = 'i', long = "input")]
    input_file: Option<PathBuf>,

    #[arg(short = 'o', long = "output")]
    output_file: Option<PathBuf>,

    #[arg(long, default_value = "true")]
    hex: bool,

    #[arg(long, default_value = "false")]
    ignore_checksum: bool,

    #[arg(long)]
    error_log: Option<PathBuf>,

    #[arg(long, default_value = "false")]
    skip_invalid: bool,

    #[arg(long, default_value = "false")]
    verbose_errors: bool,
}

fn try_bip39_english(mnemonic_str: &str) -> Option<Vec<u8>> {
    // Пробуем стандартный BIP39 English
    if let Ok(mnemonic) = Mnemonic::from_str(mnemonic_str) {
        return Some(mnemonic.to_entropy());
    }
    None
}

fn analyze_mnemonic(mnemonic_str: &str) -> String {
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    let wordlist = Language::English.word_list();
    
    let word_count = words.len();
    let mut invalid_words = Vec::new();
    
    for word in &words {
        if wordlist.iter().position(|&w| w == *word).is_none() {
            invalid_words.push(*word);
        }
    }
    
    if !invalid_words.is_empty() {
        format!("Неверные слова (не BIP39 English): {:?}. Попробованы все языки BIP39", 
                invalid_words.iter().take(3).collect::<Vec<_>>())
    } else if ![12, 15, 18, 21, 24].contains(&word_count) {
        format!("Неверное количество слов: {} (BIP39 требует 12/15/18/21/24 слов)", word_count)
    } else {
        "Неверная контрольная сумма BIP39 (попробованы все языки)".to_string()
    }
}

fn decode_mnemonic_ignore_checksum(mnemonic_str: &str) -> Result<Vec<u8>, String> {
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    
    // Получаем словарь BIP39
    let wordlist = Language::English.word_list();
    
    // Преобразуем слова в индексы
    let mut indices = Vec::new();
    for word in &words {
        match wordlist.iter().position(|&w| w == *word) {
            Some(idx) => indices.push(idx as u16),
            None => {
                return Err(analyze_mnemonic(mnemonic_str));
            }
        }
    }
    
    // Преобразуем индексы в биты
    let total_bits = indices.len() * 11;
    let mut bits = vec![false; total_bits];
    
    for (i, &index) in indices.iter().enumerate() {
        for j in 0..11 {
            let bit_pos = i * 11 + j;
            bits[bit_pos] = (index & (1 << (10 - j))) != 0;
        }
    }
    
    // Проверяем корректное количество слов
    match words.len() {
        12 | 15 | 18 | 21 | 24 => {},
        _ => return Err(format!("Неподдерживаемое количество слов: {}", words.len())),
    };
    
    // Извлекаем энтропию (все биты, включая чексум)
    // Для режима ignore-checksum мы берем ВСЕ биты
    let num_bytes = (total_bits + 7) / 8; // Округление вверх
    let mut entropy = vec![0u8; num_bytes];
    for (i, chunk) in bits.chunks(8).enumerate() {
        let mut byte = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - j);
            }
        }
        entropy[i] = byte;
    }
    
    Ok(entropy)
}

fn process_mnemonic(mnemonic_str: &str, hex: bool, ignore_checksum: bool) -> Result<String, String> {
    // Сначала пробуем стандартный BIP39 English
    if let Some(entropy) = try_bip39_english(mnemonic_str) {
        let entropy_str = if hex {
            hex::encode(&entropy)
        } else {
            format!("{:?}", entropy)
        };
        return Ok(entropy_str);
    }
    
    // Если не сработало, пробуем ignore_checksum режим
    let entropy = if ignore_checksum {
        decode_mnemonic_ignore_checksum(mnemonic_str)?
    } else {
        // Возвращаем понятную ошибку
        return Err(analyze_mnemonic(mnemonic_str));
    };
    
    let entropy_str = if hex {
        hex::encode(&entropy)
    } else {
        format!("{:?}", entropy)
    };
    Ok(entropy_str)
}

enum ProcessResult {
    Success(String),
    Error { message: String, mnemonic: String },
}

fn main() {
    let args = Args::parse();

    let mnemonics: Vec<String> = if let Some(input_path) = &args.input_file {
        match fs::read_to_string(input_path) {
            Ok(content) => {
                let data: Vec<String> = content.lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                
                if args.output_file.is_some() {
                    println!("📂 Загружено строк: {}", data.len());
                }
                
                data
            }
            Err(e) => {
                eprintln!("Ошибка при чтении файла {:?}: {}", input_path, e);
                std::process::exit(1);
            }
        }
    } else if let Some(m) = &args.mnemonic {
        vec![m.clone()]
    } else {
        println!("Введите мнемоническую фразу:");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Не удалось прочитать ввод");
        vec![input.trim().to_string()]
    };

    let total_count = mnemonics.len();
    
    // Создаём прогресс-бар только если записываем в файл
    let progress_bar = if args.output_file.is_some() && total_count > 1 {
        let pb = ProgressBar::new(total_count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap()
                .progress_chars("#>-")
        );
        Some(pb)
    } else {
        None
    };

    // Параллельная обработка
    let results: Vec<(usize, ProcessResult)> = mnemonics
        .par_iter()
        .enumerate()
        .map(|(idx, mnemonic_str)| {
            let result = match process_mnemonic(mnemonic_str, args.hex, args.ignore_checksum) {
                Ok(entropy_str) => ProcessResult::Success(entropy_str),
                Err(e) => ProcessResult::Error { 
                    message: e, 
                    mnemonic: mnemonic_str.to_string() 
                },
            };
            
            if let Some(ref pb) = progress_bar {
                pb.inc(1);
            }
            
            (idx, result)
        })
        .collect();

    if let Some(pb) = progress_bar {
        pb.finish_and_clear();
    }

    // Сортируем результаты по индексу для сохранения порядка
    let mut sorted_results = results;
    sorted_results.sort_by_key(|(idx, _)| *idx);

    let mut success_results = Vec::new();
    let mut error_results = Vec::new();

    // Обрабатываем результаты
    for (idx, result) in sorted_results {
        match result {
            ProcessResult::Success(entropy_str) => {
                if args.output_file.is_none() {
                    println!("\n=== Результат {} ===", idx + 1);
                    println!("Мнемоническая фраза: {}", mnemonics[idx]);
                    println!("Энтропия: {}", entropy_str);
                }
                success_results.push(entropy_str);
            }
            ProcessResult::Error { message, mnemonic } => {
                if args.output_file.is_none() {
                    eprintln!("\n=== Ошибка {} ===", idx + 1);
                    eprintln!("Мнемоническая фраза: {}", mnemonic);
                    eprintln!("Ошибка: {}", message);
                }
                error_results.push((mnemonic, message));
            }
        }
    }

    if let Some(output_path) = &args.output_file {
        match fs::File::create(output_path) {
            Ok(mut file) => {
                for result in &success_results {
                    if let Err(e) = writeln!(file, "{}", result) {
                        eprintln!("Ошибка при записи в файл {:?}: {}", output_path, e);
                        std::process::exit(1);
                    }
                }
                println!("✓ Результаты сохранены в файл: {:?}", output_path);
                println!("  Обработано успешно: {} мнемоник", success_results.len());
                if !error_results.is_empty() {
                    println!("  Ошибок: {}", error_results.len());
                }
            }
            Err(e) => {
                eprintln!("Ошибка при создании файла {:?}: {}", output_path, e);
                std::process::exit(1);
            }
        }
    }

    // Сохраняем ошибки в отдельный файл, если указан
    if let Some(error_log_path) = &args.error_log {
        if !error_results.is_empty() {
            match fs::File::create(error_log_path) {
                Ok(mut file) => {
                    for (mnemonic, message) in &error_results {
                        let line = if args.verbose_errors {
                            format!("{} | {}", mnemonic, message)
                        } else {
                            mnemonic.clone()
                        };
                        if let Err(e) = writeln!(file, "{}", line) {
                            eprintln!("Ошибка при записи в лог ошибок {:?}: {}", error_log_path, e);
                            std::process::exit(1);
                        }
                    }
                    println!("📝 Лог ошибок сохранён в файл: {:?}", error_log_path);
                }
                Err(e) => {
                    eprintln!("Ошибка при создании файла лога {:?}: {}", error_log_path, e);
                    std::process::exit(1);
                }
            }
        }
    }

    // Показываем предупреждение если много ошибок и это не режим skip_invalid
    if !args.skip_invalid && !error_results.is_empty() {
        let error_rate = (error_results.len() as f64 / total_count as f64) * 100.0;
        if error_rate > 50.0 {
            println!("\n⚠️  ВНИМАНИЕ: {:.1}% мнемоник невалидны!", error_rate);
            println!("   Возможно это не BIP39 мнемоники (Electrum, Monero и т.д.)");
            println!("   Используйте --skip-invalid для игнорирования ошибок");
            println!("   Используйте --error-log FILE для сохранения невалидных мнемоник");
        }
    }

    // Завершаем с кодом ошибки только если НЕТ успешных результатов И не установлен skip_invalid
    if !error_results.is_empty() && success_results.is_empty() && !args.skip_invalid {
        eprintln!("\n❌ Все мнемоники завершились с ошибкой!");
        std::process::exit(1);
    }
}

