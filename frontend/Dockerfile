# Serrier dashboard — Next.js standalone. NEXT_PUBLIC_API bakas in vid build (klient-kod),
# så den sätts som build-arg och default pekar på backend-tjänsten i compose.
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_API=http://localhost:8000
ENV NEXT_PUBLIC_API=${NEXT_PUBLIC_API}
RUN npm run build

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
