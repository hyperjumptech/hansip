# Hansip Front-end

## About

This is the front end web application for Hansip.

## Tech stack

1. [Next.JS](https://nextjs.org/).
2. [SWR](https://github.com/vercel/swr): to manage data fetching.
3. [Tailwind CSS](https://tailwindcss.com/): for styling.

## Requirements

1. [NodeJS](https://nodejs.org/en/).
2. [Yarn](https://yarnpkg.com/).
3. Hansip API server.

## Getting Started

1. Clone this repository
2. Run `yarn`
3. Run `cp .env.local.template .env.local`
4. Edit the Hansip API URL in .env.local if needed.
5. Run Hansip API server if needed.
6. Run `yarn dev`

## Directory Structure

1. `pages`: each of the files in this directory is associated with [a route based on its file name](https://nextjs.org/docs/basic-features/pages).
2. `data`: files related to data fetching, data types, etc.
3. `components`: React components that are used in the web application.

## Deployment

1. Edit the value of `NEXT_PUBLIC_API_URL` in the `.env.local` file.
2. Run `yarn build` to create optimized production build.
3. Deploy to production server.
4. Run `yarn start` to run the web application.

## TODO

1. Add tests.
2. Fix storybook.
