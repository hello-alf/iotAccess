Comandos a utilizar para hacer deploy


export AWS_PROFILE=USER_3_UPASSER
sam deploy

aws cognito-idp sign-up \
--client-id POOL_CLIENT_ID \
--username user@upasser.com \
--password 'password123' \
--user-attributes Name=email,Value=user@upasser.com

aws cognito-idp admin-confirm-sign-up \
--user-pool-id UserPoolId \
--username user@upasser.com