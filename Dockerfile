FROM node:24.5.0
WORKDIR /app
COPY package*.json .
CMD ["sh", "-c", "npm ci && npm run dev"]
