FROM node:14

RUN mkdir -p /hansip
COPY . /hansip
WORKDIR /hansip

RUN yarn
COPY .env.local.template .env.local
RUN yarn build
EXPOSE 3000
CMD ["yarn","start","-p","3000"]