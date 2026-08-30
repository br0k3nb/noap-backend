use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct IpGeoResponse {
    country_name: Option<String>,
    country_code2: Option<String>,
    state_prov: Option<String>,
    city: Option<String>,
}

pub struct GeoInfo {
    pub country_name: String,
    pub country_code: String,
    pub state_prov: String,
    pub city: String,
}

pub async fn fetch_geo(ip: &str, api_key: &str) -> GeoInfo {
    if api_key.is_empty() {
        return GeoInfo {
            country_name: "Unknown".to_string(),
            country_code: "US".to_string(),
            state_prov: "Unknown".to_string(),
            city: "Unknown".to_string(),
        };
    }
    let url = format!(
        "https://api.ipgeolocation.io/ipgeo?apiKey={}&ip={}",
        api_key, ip
    );
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await;
    if let Ok(r) = resp {
        if let Ok(data) = r.json::<IpGeoResponse>().await {
            return GeoInfo {
                country_name: data.country_name.unwrap_or_else(|| "Unknown".to_string()),
                country_code: data.country_code2.unwrap_or_else(|| "US".to_string()),
                state_prov: data.state_prov.unwrap_or_else(|| "Unknown".to_string()),
                city: data.city.unwrap_or_else(|| "Unknown".to_string()),
            };
        }
    }
    GeoInfo {
        country_name: "Unknown".to_string(),
        country_code: "US".to_string(),
        state_prov: "Unknown".to_string(),
        city: "Unknown".to_string(),
    }
}
