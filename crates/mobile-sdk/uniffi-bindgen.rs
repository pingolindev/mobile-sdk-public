// Copyright (c) 2025 Pingolin LLC
//
// This file is part of Pingolin Mobile SDK.
//
// Pingolin Mobile SDK is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Pingolin Mobile SDK is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Pingolin Mobile SDK. If not, see <https://www.gnu.org/licenses/>.

use camino::Utf8PathBuf;
use clap::Parser;
use uniffi_bindgen::bindings::{KotlinBindingGenerator, SwiftBindingGenerator};
use uniffi_bindgen::EmptyCrateConfigSupplier;

#[derive(Parser)]
#[command(name = "uniffi-bindgen")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Generate {
        #[arg(long)]
        library: Utf8PathBuf,
        #[arg(long)]
        language: String,
        #[arg(long)]
        out_dir: Utf8PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { library, language, out_dir } => {
            std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");

            let config_supplier = EmptyCrateConfigSupplier;

            match language.as_str() {
                "kotlin" => {
                    uniffi_bindgen::library_mode::generate_bindings(
                        &library,
                        None,
                        &KotlinBindingGenerator,
                        &config_supplier,
                        None,
                        &out_dir,
                        false,
                    ).expect("Failed to generate Kotlin bindings");
                }
                "swift" => {
                    uniffi_bindgen::library_mode::generate_bindings(
                        &library,
                        None,
                        &SwiftBindingGenerator,
                        &config_supplier,
                        None,
                        &out_dir,
                        false,
                    ).expect("Failed to generate Swift bindings");
                }
                _ => panic!("Unsupported language: {}", language),
            };

            println!("✅ {} bindings generated in {:?}", language, out_dir);
        }
    }
}
