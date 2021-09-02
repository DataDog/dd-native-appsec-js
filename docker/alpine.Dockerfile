FROM node:14-alpine

RUN apk add py3-pip make g++

WORKDIR /build
COPY ./package.json .
COPY ./package-lock.json .

RUN npm ci --ignore-scripts
COPY . .
CMD ["npm", "run", "build-test-bundle"]
