import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import { config as dotenvConfig } from "dotenv";
import bodyParser from "body-parser";
import multer from "multer";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import fs from 'fs';
import { fileURLToPath } from 'url'; // For __dirname workaround if using ES Modules

dotenvConfig();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from "uploads" folder
app.use("/uploads", express.static("uploads"));

// MongoDB Connection
const envUserName = process.env.MONGODB_USERNAME;
const envPassWord = process.env.MONGODB_PASSWORD;

mongoose
  .connect(`mongodb+srv://${envUserName}:${envPassWord}@mainnikedb.jx4pwkk.mongodb.net/beat`)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

// Multer setup to save files in /uploads folder
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const fieldName = file.fieldname; // 'image' or 'audio'

    // Use a sanitized version of the title (replaces spaces/special chars)
    const rawTitle = req.body.title || "untitled";
    const sanitizedTitle = rawTitle.toLowerCase().replace(/\s+/g, "-").replace(/[^\w\-]/g, "");

    cb(null, `${sanitizedTitle}-${fieldName}${ext}`);
  },
});


const upload = multer({ storage });


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

// Mongoose Schema with file paths (not buffer)
const trackSchema = new mongoose.Schema({
  title: String,
  singer: String,
  image: String, // path to image file
  audio: String, // path to audio file
});

const Track = mongoose.model("Track", trackSchema);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
});

const Admin = mongoose.model("Admin", adminSchema);

const suggestionSchema = new mongoose.Schema({
 song: {type: String, required: true},
 artist: {type: String, required: true}
})

const Suggestion = mongoose.model("Suggestion", suggestionSchema);


// Upload route
app.post("/upload", verifyAdmin, upload.fields([{ name: "image" }, { name: "audio" }]), async (req, res) => {
  try {
    const { title, singer } = req.body;

    if (!req.files?.image || !req.files?.audio || !title || !singer) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const imagePath = `/uploads/${req.files.image[0].filename}`;
    const audioPath = `/uploads/${req.files.audio[0].filename}`;

    const newTrack = new Track({
      title,
      singer,
      image: imagePath,
      audio: audioPath,
    });

    await newTrack.save();

    res.status(201).json({ message: "Track uploaded successfully", track: newTrack });
  } catch (error) {
    console.error("Error uploading track:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete('/track/:title', verifyAdmin, async (req, res) => {
  try {
    const { title } = req.params;

    // Find the track
    const track = await Track.findOne({ title });

    if (!track) {
      return res.status(404).json({ error: "Track not found" });
    }

    // Paths to delete
    const imagePath = path.join(process.cwd(), track.image); // "./uploads/image.png"
    const audioPath = path.join(process.cwd(), track.audio); // "./uploads/audio.mp3"

    // Delete files if they exist
    if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
    if (fs.existsSync(audioPath)) fs.unlinkSync(audioPath);

    // Delete track document
    await Track.deleteOne({ title });

    res.json({ message: 'Track and associated files deleted successfully.' });

  } catch (error) {
    console.error('Error deleting track:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Sugguestion post Req
app.post('/suggestion', async (req, res) => {
  try {
    const { song, artist } = req.body;

    if (!song || !artist) {
      return res.status(400).json({ error: 'Song and Artist fields are required.' });
    }

    const newSuggestion = new Suggestion({ song, artist });
    await newSuggestion.save();

    res.status(201).json({ message: 'Suggestion submitted successfully!' });
  } catch (err) {
    console.error('Error while saving suggestion:', err);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// Fetch all tracks (title, singer, audio path)
app.get("/tracks", async (req, res) => {
  try {
    const tracks = await Track.find().select("title singer image audio -_id");
    res.json(tracks);
  } catch (error) {
    console.error("Error fetching tracks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Test Route
app.get("/", (req, res) => {
  res.send("<h1>Hello World</h1>");
});



// Register Admin (run only once)
app.post("/register-admin", async (req, res) => {
  const { email, password } = req.body;
  const existing = await Admin.findOne({ email });
  if (existing) return res.status(400).json({ error: "Admin already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = new Admin({ email, password: hashedPassword });
  await admin.save();

  res.json({ message: "Admin registered successfully" });
});

// Login Admin
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;
  const user = await Admin.findOne({ email });
  // console.log("Frontend sent:", email, password); // Debug


  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "2h",
  });

  res.json({ token });
});



const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
