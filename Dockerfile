FROM node:24-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN apk upgrade --no-cache

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
EXPOSE 3000
USER node
CMD ["npm", "start"]