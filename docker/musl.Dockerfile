FROM node:14-alpine@sha256:8c94a0291133e16b92be5c667e0bc35930940dfa7be544fb142e25f8e4510a45

RUN apk add py3-pip make g++

WORKDIR /build
COPY ./package.json .
COPY ./package-lock.json .

RUN npm ci --ignore-scripts
COPY . .
CMD ["npm", "run", "build-test-bundle"]
