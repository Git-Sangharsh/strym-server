import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import { config as dotenvConfig } from "dotenv";
import bodyParser from "body-parser";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import path from "path";

dotenvConfig();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose
  .connect(
    `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@mainnikedb.jx4pwkk.mongodb.net/beat`
  )
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer Cloudinary Storage Setup
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    const folder = "beat-tracks";
    const rawTitle = req.body.title || "untitled";
    const sanitizedTitle = rawTitle.toLowerCase().replace(/\s+/g, "-").replace(/[^\w\-]/g, "");

    return {
      folder,
      resource_type: file.mimetype.startsWith("audio") ? "video" : "image",
      public_id: `${sanitizedTitle}-${file.fieldname}-${Date.now()}`,
    };
  },
});

const upload = multer({ storage });

// Mongoose Schemas
const trackSchema = new mongoose.Schema({
  title: String,
  singer: String,
  image: String,
  audio: String,
});

const Track = mongoose.model("Track", trackSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
});

const Admin = mongoose.model("Admin", adminSchema);

const suggestionSchema = new mongoose.Schema({
  song: { type: String, required: true },
  artist: { type: String, required: true },
});

const Suggestion = mongoose.model("Suggestion", suggestionSchema);

// Middleware: Verify Admin
const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin") return res.status(403).json({ error: "Access denied" });

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Upload Route
app.post("/upload", verifyAdmin, upload.fields([{ name: "image" }, { name: "audio" }]), async (req, res) => {
  try {
    const { title, singer } = req.body;

    if (!req.files?.image || !req.files?.audio || !title || !singer) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const imageUrl = req.files.image[0].path;
    const audioUrl = req.files.audio[0].path;

    const newTrack = new Track({
      title,
      singer,
      image: imageUrl,
      audio: audioUrl,
    });

    await newTrack.save();

    res.status(201).json({ message: "Track uploaded successfully", track: newTrack });
  } catch (error) {
    console.error("Error uploading track:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Delete Track
app.delete("/track/:title", verifyAdmin, async (req, res) => {
  try {
    const { title } = req.params;
    const track = await Track.findOne({ title });

    if (!track) return res.status(404).json({ error: "Track not found" });

    await Track.deleteOne({ title });

    res.json({ message: "Track deleted from database (media still exists on Cloudinary)." });
  } catch (error) {
    console.error("Error deleting track:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Submit Suggestion
app.post("/suggestion", async (req, res) => {
  try {
    const { song, artist } = req.body;

    if (!song || !artist) {
      return res.status(400).json({ error: "Song and Artist fields are required." });
    }

    const newSuggestion = new Suggestion({ song, artist });
    await newSuggestion.save();

    res.status(201).json({ message: "Suggestion submitted successfully!" });
  } catch (err) {
    console.error("Error while saving suggestion:", err);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

// Get All Tracks
app.get("/tracks", async (req, res) => {
  try {
    const tracks = await Track.find();
    res.json(tracks);
  } catch (error) {
    console.error("Error fetching tracks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Admin Registration (one-time use)
app.post("/register-admin", async (req, res) => {
  const { email, password } = req.body;
  const existing = await Admin.findOne({ email });
  if (existing) return res.status(400).json({ error: "Admin already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = new Admin({ email, password: hashedPassword });
  await admin.save();

  res.json({ message: "Admin registered successfully" });
});

// Admin Login
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;
  const user = await Admin.findOne({ email });

  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });

  res.json({ token });
});

// Test Route
app.get("/", (req, res) => {
  res.send("<h1>Beat API Server is Running</h1>");
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
