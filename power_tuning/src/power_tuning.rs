#[macro_export]
macro_rules! impl_power_tuning {
    ($power_tuning_func:ident, $lambda_name:expr, $generate_payload:ident, $is_handshake:expr, $api_endpoint_url:expr) => {
        #[allow(unused)]
        async fn $power_tuning_func(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
            let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
            let aws_config = aws_config::from_env().region(region_provider).load().await;
            let client = Client::new(&aws_config);
            let memsizes = [128, 256, 384, 512, 650, 700, 750, 800, 850, 900];
            let iterations = 4;
            let mut outcomes = vec![vec![0u128; iterations]; memsizes.len()];
            for m in 0..memsizes.len() {
                client.update_function_configuration()
                    .function_name($lambda_name)
                    .set_memory_size(Some(memsizes[m] as i32))
                    .send()
                    .await
                    .unwrap();
                sleep(Duration::from_millis(5000)).await;

                for i in 0..iterations {
                    let inner_payload = $generate_payload();
                    let payload = encrypt_and_sign_payload(inner_payload, $is_handshake, server_keys.clone());

                    let start = Instant::now();
                    let response = req_client.post($api_endpoint_url)
                        .header("X-Signature", payload.signature.to_base64(false))
                        .body(payload.encrypted)
                        .send()
                        .await
                        .unwrap();
                    let end = Instant::now();
                    outcomes[m][i] = end.duration_since(start).as_millis();

                    sleep(Duration::from_millis(1000)).await;
                }
            }

            println!("{} Outcomes:", $lambda_name);
            let costs_per_memory_allocated = calculate_costs(&memsizes, outcomes.clone());
            for i in 0..costs_per_memory_allocated.len() {
                println!("With {} MB of RAM\n{} ms average time\n${} average cost", memsizes[i], costs_per_memory_allocated[i].0, costs_per_memory_allocated[i].1);
            }
            println!("\nAll results:\n{:?}", outcomes);
            Ok(())
        }
    };
}

const GB_PER_MB: f64 = 0.0009765625;
const GB_S_BASE_COST: f64 = 0.0000133334;

pub fn calculate_costs(memsizes: &[usize], outcomes: Vec<Vec<u128>>) -> Vec<(u128, f64)> {
    let mut costs: Vec<(u128, f64)> = Vec::with_capacity(memsizes.len());
    for i in 0..memsizes.len() {
        let memory = memsizes[i];
        let mut sum = 0;
        for j in 0..outcomes[i].len() {
            sum += outcomes[i][j];
        }
        let average_time_ms = sum / outcomes[i].len() as u128;

        let average_time_s = average_time_ms / 1000;

        let memory_allocated = memory as f64 * GB_PER_MB;
        let total_compute_gb_s = memory_allocated * average_time_s as f64;

        let cost_per_million_invocations = GB_S_BASE_COST * total_compute_gb_s * 1_000_000f64;
        costs.push((average_time_ms, cost_per_million_invocations));
    }
    costs
}