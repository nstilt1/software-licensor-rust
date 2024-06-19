#[cfg(feature = "dynamodb")]
pub mod maps;
#[cfg(feature = "dynamodb")]
pub mod maps_mk2;

#[cfg_attr(feature = "dynamodb", macro_export)]
macro_rules! init_dynamodb_client {
    () => {
        {
            let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
            let aws_config = utils::aws_config::from_env().region(region_provider).load().await;
            Client::new(&aws_config)
        }
    };
}