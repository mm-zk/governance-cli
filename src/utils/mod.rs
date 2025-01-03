use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

pub mod address_verifier;
pub mod bytecode_verifier;
pub mod network_verifier;
pub mod selector_verifier;

pub async fn get_contents_from_github(commit: &str, repo: &str, file_path: &str) -> String {
    let url = format!(
        "https://raw.githubusercontent.com/{repo}/{}/{file_path}",
        commit
    );

    let cache_path = Path::new("cache");
    fs::create_dir_all(cache_path).expect("Failed to create cache directory");

    let cache_file_path = cache_path.join(format!(
        "{}-{}.json",
        Path::new(file_path).file_name().unwrap().to_str().unwrap(),
        commit
    ));

    if !cache_file_path.exists() {
        let response = reqwest::get(url).await.unwrap();

        let mut file = File::create(cache_file_path.clone()).expect("Failed to create cache file");
        let data = response.bytes().await.unwrap();
        file.write_all(&data).unwrap();
    }

    let data = fs::read_to_string(&cache_file_path).expect("Failed to read cache file");
    return data;
}
