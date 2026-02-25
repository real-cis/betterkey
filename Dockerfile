# Build
FROM ghcr.io/edgelesssys/ego-dev:v1.8.1

ARG SIGNERKEY=dev/conf/test-private.pem
ARG ENCLAVE_PROPS=dev/conf/enclave.properties

WORKDIR /app
RUN mkdir /sealed
COPY . ./
RUN sed -e "s|_SIGNERKEY_|${SIGNERKEY}|g" \
    -e "s|_ENCLAVE_PROPS_|${ENCLAVE_PROPS}|g" enclave.json.template >enclave.json
RUN ego-go build -tags=ionos cmd/bootstrap/main.go
RUN ego sign main
RUN ego signerid main

# Run with deploy container
FROM ghcr.io/edgelesssys/ego-deploy:v1.8.1

WORKDIR /app
COPY --from=0 /app/main /app/main
CMD ["ego", "run", "main", "--config", "/enclave.properties"]