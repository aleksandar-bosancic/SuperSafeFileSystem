userinfo=`cat users.txt`
users=${userinfo}
for user in $users
do
	rm certs/$user.pem
	rm requests/$user.csr
	rm private/$user.key
	rm public/$user.key
done
rm -r newcerts
mkdir newcerts
rm users.txt
touch users.txt