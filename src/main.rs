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
}

fn process_mnemonic(mnemonic_str: &str, hex: bool) -> Result<String, String> {
    let mnemonic = match Mnemonic::from_str(mnemonic_str) {
        Ok(m) => m,
        Err(e) => {
            return Err(format!("Ошибка при парсинге мнемонической фразы: {}", e));
        }
    };

    let entropy = mnemonic.to_entropy();
    
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

        match process_mnemonic(mnemonic_str, args.hex) {
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

