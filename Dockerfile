FROM node:22-alpine

WORKDIR /app

COPY outputs/passwort-notizen-app/ ./

ENV HOST=0.0.0.0
ENV PORT=4173

EXPOSE 4173

CMD ["node", "server.js"]
