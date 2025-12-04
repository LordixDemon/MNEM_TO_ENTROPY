use bip39::{Mnemonic, Language};
use clap::Parser;
use std::str::FromStr;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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
            None => return Err(format!("Слово '{}' не найдено в словаре BIP39", word)),
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
    let entropy = if ignore_checksum {
        decode_mnemonic_ignore_checksum(mnemonic_str)?
    } else {
        let mnemonic = match Mnemonic::from_str(mnemonic_str) {
            Ok(m) => m,
            Err(e) => {
                return Err(format!("Ошибка при парсинге мнемонической фразы: {}", e));
            }
        };
        mnemonic.to_entropy()
    };
    
    if hex {
        Ok(hex::encode(&entropy))
    } else {
        Ok(format!("{:?}", entropy))
    }
}

fn main() {
    let args = Args::parse();

    let mnemonics: Vec<String> = if let Some(input_path) = &args.input_file {
        match fs::read_to_string(input_path) {
            Ok(content) => {
                content.lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
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

    let mut results = Vec::new();
    let mut has_errors = false;

    for (idx, mnemonic_str) in mnemonics.iter().enumerate() {
        if mnemonic_str.is_empty() {
            continue;
        }

        match process_mnemonic(mnemonic_str, args.hex, args.ignore_checksum) {
            Ok(entropy_str) => {
                if args.output_file.is_none() {
                    println!("\n=== Результат {} ===", idx + 1);
                    println!("Мнемоническая фраза: {}", mnemonic_str);
                    println!("Энтропия: {}", entropy_str);
                }
                results.push(entropy_str);
            }
            Err(e) => {
                eprintln!("\n=== Ошибка {} ===", idx + 1);
                eprintln!("Мнемоническая фраза: {}", mnemonic_str);
                eprintln!("Ошибка: {}", e);
                has_errors = true;
            }
        }
    }

    if let Some(output_path) = &args.output_file {
        match fs::File::create(output_path) {
            Ok(mut file) => {
                for result in &results {
                    if let Err(e) = writeln!(file, "{}", result) {
                        eprintln!("Ошибка при записи в файл {:?}: {}", output_path, e);
                        std::process::exit(1);
                    }
                }
                println!("\n✓ Результаты сохранены в файл: {:?}", output_path);
                println!("  Обработано: {} мнемоник", results.len());
            }
            Err(e) => {
                eprintln!("Ошибка при создании файла {:?}: {}", output_path, e);
                std::process::exit(1);
            }
        }
    }

    if has_errors {
        std::process::exit(1);
    }
}

