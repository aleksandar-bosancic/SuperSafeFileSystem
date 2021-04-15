username=$1
openssl genrsa -out private/$username.key 2048
openssl req -new -key private/$username.key -out requests/$username.csr -config openssl.cnf
openssl ca -in requests/$username.csr -out certs/$username.pem -config openssl.cnf
openssl x509 -in certs/$username.pem -pubkey -noout > public/$username.key