# IT Study Hub

Express + SQLite backend with the dashboard served from `public/`.

## Run
    npm install
    npm start
Open http://localhost:3000

Requires Node 18+. The database is created automatically at `data/studyhub.db`.
Optional: set `PORT` and `JWT_SECRET` environment variables.

## API
POST /api/auth/register  {name,email,password}
POST /api/auth/login     {email,password}
GET  /api/auth/me
GET/POST /api/study-plans
PUT/DELETE /api/study-plans/:id   (Authorization: Bearer <token>)
