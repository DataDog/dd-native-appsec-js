FROM node:14-alpine@sha256:8c94a0291133e16b92be5c667e0bc35930940dfa7be544fb142e25f8e4510a45

WORKDIR /test
COPY . .
CMD ["npm", "t"]
