#head -1 /etc/ssl/ike.ca/ikeca.passwd | \
openssl ca -config horst-ssl.cnf \
	-in horst.csr \
	-outdir /etc/ssl/ike.ca/test/new \
	-out new/horst.crt \
	-cert ../ca.crt \
	-keyfile ../private/ca.key \
	-extensions x509v3_FQDN

