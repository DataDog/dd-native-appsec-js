ARG BASE_IMAGE
FROM $BASE_IMAGE

WORKDIR /build
COPY ./package.json .
COPY ./package-lock.json .

RUN npm ci --ignore-scripts
COPY . .
CMD ["npm", "run", "build-test-bundle"]
