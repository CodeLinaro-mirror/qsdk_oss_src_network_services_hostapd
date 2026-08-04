#!/bin/sh
#
# Generate the ML-DSA (post-quantum) test certificates. This requires an
# OpenSSL version that implements ML-DSA (OpenSSL 3.5 or newer).

OPENSSL=openssl

ALG=ML-DSA-87

# The hwsim test environment runs with a fixed clock, so use an explicit
# validity period that is wide enough to cover it.
NOT_BEFORE=20200101000000Z
NOT_AFTER=20350101000000Z

if ! $OPENSSL list -signature-algorithms | grep -q "$ALG"; then
	echo "$OPENSSL does not support $ALG"
	exit 1
fi

echo
echo "---[ Root CA ]----------------------------------------------------------"
echo

cat mldsa-openssl.cnf |
	sed "s/#@CN@/commonName_default = ML-DSA Root CA/" \
	> mldsa-openssl.cnf.tmp
$OPENSSL genpkey -algorithm $ALG -out mldsa-ca.key
$OPENSSL req -config mldsa-openssl.cnf.tmp -batch -x509 -new -key mldsa-ca.key -out mldsa-ca.pem -outform PEM -not_before $NOT_BEFORE -not_after $NOT_AFTER
mkdir -p mldsa-ca/certs mldsa-ca/crl mldsa-ca/newcerts mldsa-ca/private
touch mldsa-ca/index.txt
rm mldsa-openssl.cnf.tmp

echo
echo "---[ Server ]-----------------------------------------------------------"
echo

cat mldsa-openssl.cnf |
	sed "s/#@CN@/commonName_default = server.w1.fi/" |
	sed "s/#@ALTNAME@/subjectAltName=critical,DNS:server.w1.fi/" \
	> mldsa-openssl.cnf.tmp
$OPENSSL genpkey -algorithm $ALG -out mldsa-server.key
$OPENSSL req -config mldsa-openssl.cnf.tmp -batch -new -nodes -key mldsa-server.key -out mldsa-server.req -outform PEM
$OPENSSL ca -config mldsa-openssl.cnf.tmp -batch -keyfile mldsa-ca.key -cert mldsa-ca.pem -create_serial -in mldsa-server.req -out mldsa-server.pem -extensions ext_server -startdate $NOT_BEFORE -enddate $NOT_AFTER -notext
rm mldsa-openssl.cnf.tmp mldsa-server.req

echo
echo "---[ User ]-------------------------------------------------------------"
echo

cat mldsa-openssl.cnf |
	sed "s/#@CN@/commonName_default = user/" |
	sed "s/#@ALTNAME@/subjectAltName=email:user@w1.fi/" \
	> mldsa-openssl.cnf.tmp
$OPENSSL genpkey -algorithm $ALG -out mldsa-user.key
$OPENSSL req -config mldsa-openssl.cnf.tmp -batch -new -nodes -key mldsa-user.key -out mldsa-user.req -outform PEM
$OPENSSL ca -config mldsa-openssl.cnf.tmp -batch -keyfile mldsa-ca.key -cert mldsa-ca.pem -create_serial -in mldsa-user.req -out mldsa-user.pem -extensions ext_client -startdate $NOT_BEFORE -enddate $NOT_AFTER -notext
rm mldsa-openssl.cnf.tmp mldsa-user.req

rm -rf mldsa-ca

echo
echo "---[ Verify ]-----------------------------------------------------------"
echo

$OPENSSL verify -CAfile mldsa-ca.pem mldsa-server.pem
$OPENSSL verify -CAfile mldsa-ca.pem mldsa-user.pem
