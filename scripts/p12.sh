cat horst.key new/horst.crt ../ca.crt | \
openssl pkcs12 -out new/horst.p12 -export 
