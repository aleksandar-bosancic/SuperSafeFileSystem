openssl genrsa -out private/private4096.key 4096
openssl req -new -key private/private4096.key -out requests/rootca.csr -config openssl.cnf -days 365
openssl ca -in requests/rootca.csr -out certs/rootca.pem -selfsign -keyfile private/private4096.key -config openssl.cnf