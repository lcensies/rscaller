GIT_ROOT="$(git rev-parse --show-toplevel)"
SIGNING_DIR="${GIT_ROOT}/target/module_signing"
SIGNATURE_NAME=rscaller
PRIVKEY_NAME="${SIGNING_DIR}/${SIGNATURE_NAME}.priv"

echo Generating module signing keys at ${SIGNING_DIR}

mkdir $SIGNING_DIR 2>/dev/null && cd $SIGNING_DIR

create_certs() {
    openssl req -new -x509 -newkey rsa:2048 -keyout $SIGNATURE_NAME.priv -outform DER -out ${PRIVKEY_NAME}.der -nodes -days 36500 -subj "/CN=testorg/"
    chmod 600 $SIGNATURE_NAME.priv 
}

test -f ${PRIVKEY_NAME} && echo "Keys already exist"
test -f ${PRIVKEY_NAME} || create_certs
