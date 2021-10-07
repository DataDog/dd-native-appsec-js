ARG BASE_IMAGE
FROM $BASE_IMAGE

WORKDIR /test
COPY . .

RUN node scripts/rename.js
RUN npm i -S datadog-native-appsec-0.0.0.tgz
RUN ls -l ./node_modules/@datadog/native-appsec/vendor/*

CMD ["npm", "t"]
