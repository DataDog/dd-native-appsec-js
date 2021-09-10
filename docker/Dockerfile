FROM node:14@sha256:4164d987bfceb62b17db4938d535dd31fc50d6ee0b4e00ac7a774f82af408d48

WORKDIR /build
COPY ./package.json .
COPY ./package-lock.json .

RUN npm ci --ignore-scripts
COPY . .
CMD ["npm", "run", "build-test-bundle"]
