const express = require("express");
const cors = require("cors");
const connectDb = require("./config/dbConnection");
const dotenv = require("dotenv").config();

const app = express();
const port = process.env.PORT || 5001;
const frontendUrl = [process.env.FRONTEND_URI, "http://localhost:3000"];
connectDb();

app.use(
  cors({
    origin: "*",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true,
  })
);
app.use(express.json());

app.use("/api/users", require("./src/routes/UserRoutes"));

app.get("/", (req, res) => {
  res.send("<h1>Welcome to HealthAI</h1>");
});

app.listen(port, () => {
  console.log(`Server is running at port ${port}`);
});
