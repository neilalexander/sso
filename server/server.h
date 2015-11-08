struct sso_config
{
    char realm_publickey[crypto_box_PUBLICKEYBYTES];
    char realm_secretkey[crypto_box_SECRETKEYBYTES];
};
