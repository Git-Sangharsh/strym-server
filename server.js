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
    const sanitizedTitle = rawTitle
      .toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^\w\-]/g, "");

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
// playlist Schema
const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  tracks: [{ type: mongoose.Schema.Types.ObjectId, ref: "Track" }],
});

// userSchema
const userSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  playlists: [playlistSchema], // Add playlists to user schema
  likedTracks: [{ type: mongoose.Schema.Types.ObjectId, ref: "Track" }], // storing like songs
});

const userModel = mongoose.model("user", userSchema);

// Middleware: Verify Admin
const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin")
      return res.status(403).json({ error: "Access denied" });

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Upload Route
app.post(
  "/upload",
  verifyAdmin,
  upload.fields([{ name: "image" }, { name: "audio" }]),
  async (req, res) => {
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

      res
        .status(201)
        .json({ message: "Track uploaded successfully", track: newTrack });
    } catch (error) {
      console.error("Error uploading track:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

// Delete Track
app.delete("/track/:title", verifyAdmin, async (req, res) => {
  try {
    const { title } = req.params;
    const track = await Track.findOne({ title });

    if (!track) return res.status(404).json({ error: "Track not found" });

    await Track.deleteOne({ title });

    res.json({
      message:
        "Track deleted from database (media still exists on Cloudinary).",
    });
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
      return res
        .status(400)
        .json({ error: "Song and Artist fields are required." });
    }

    const newSuggestion = new Suggestion({ song, artist });
    await newSuggestion.save();

    res.status(201).json({ message: "Suggestion submitted successfully!" });
  } catch (err) {
    console.error("Error while saving suggestion:", err);
    res.status(500).json({ error: "Server error. Please try again later." });
  }
});

//  google auth
app.post("/google-auth", async (req, res) => {
  const { userName, email } = req.body;

  if (!userName || !email) {
    return res.status(400).json({ error: "Missing name or email" });
  }

  try {
    // Check if user already exists
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res
        .status(200)
        .json({ message: "User already exists", user: existingUser });
    }

    // Save new user
    const newUser = new userModel({ userName, email });
    await newUser.save();

    res.status(201).json({ message: "User saved", user: newUser });
  } catch (error) {
    console.error("Error saving user:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// play list endpoiint
app.post("/create-playlist", async (req, res) => {
  const { email, playlistName, trackIds } = req.body;

  try {
    const user = await userModel.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found" });

    // Create new playlist object
    const newPlaylist = {
      name: playlistName,
      tracks: trackIds,
    };

    // Add to user's playlists
    user.playlists.push(newPlaylist);

    await user.save();

    res.status(200).json({ message: "Playlist created", user });
  } catch (error) {
    console.error("Error creating playlist:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// delete playlist
app.post("/delete-playlist", async (req, res) => {
  const authHeader = req.headers.authorization;
  const { playlistName } = req.body;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString());
  } catch (e) {
    return res.status(400).json({ error: "Invalid token format" });
  }

  const email = decoded?.email;
  if (!email) {
    return res.status(400).json({ error: "Email not found in token" });
  }

  if (!playlistName) {
    return res.status(400).json({ error: "playlistName is required" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const initialLength = user.playlists.length;
    user.playlists = user.playlists.filter((pl) => pl.name !== playlistName);

    if (user.playlists.length === initialLength) {
      return res.status(404).json({ error: "Playlist not found" });
    }

    await user.save();

    return res.status(200).json({ message: "Playlist deleted successfully" });
  } catch (error) {
    console.error("Error deleting playlist:", error);
    return res.status(500).json({ error: "Internal Server Error" });
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

  if (!user)
    return res.status(401).json({ error: "Invalid email or password" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: "2h",
    }
  );

  res.json({ token });
});

// get all playlist
app.get("/get-playlist", async (req, res) => {
  try {
    const tracks = await Track.find();
    res.json(tracks);
  } catch (error) {
    console.error("Error fetching tracks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Test Route
app.post("/get-playlist", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = JSON.parse(
      Buffer.from(token.split(".")[1], "base64").toString()
    );

    const email = decoded?.email;
    if (!email) {
      return res.status(400).json({ error: "Invalid token" });
    }

    const user = await userModel.findOne({ email }).select("playlists");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ playlists: user.playlists });
  } catch (error) {
    console.error("Error fetching playlists:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// get specific playlist song
app.post("/get-specific-playlist", async (req, res) => {
  const authHeader = req.headers.authorization;
  const { playlistName } = req.body;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64").toString()
  );
  const email = decoded?.email;

  if (!email) {
    return res.status(400).json({ error: "Invalid token" });
  }

  if (!playlistName) {
    return res.status(400).json({ error: "playlistName is required" });
  }

  try {
    const user = await userModel.findOne({ email }).lean(); // .lean() makes the result a plain object

    if (!user) return res.status(404).json({ error: "User not found" });

    const playlist = user.playlists.find((pl) => pl.name === playlistName);
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });

    // Fetch full track documents
    const populatedTracks = await Track.find({ _id: { $in: playlist.tracks } });

    // Return the playlist with full track data
    res.status(200).json({
      playlist: {
        name: playlist.name,
        tracks: populatedTracks,
      },
    });
  } catch (error) {
    console.error("Error getting specific playlist:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/addto-playlist", async (req, res) => {
  const authHeader = req.headers.authorization;
  const { trackTitle, playlistTitle } = req.body;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64").toString()
  );

  const email = decoded?.email;
  if (!email) {
    return res.status(400).json({ error: "Invalid token" });
  }

  if (!trackTitle || !playlistTitle) {
    return res
      .status(400)
      .json({ error: "trackTitle and playlistTitle are required" });
  }

  try {
    // 1. Find the user
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // 2. Find the track by title
    const track = await Track.findOne({ title: trackTitle });
    if (!track) return res.status(404).json({ error: "Track not found" });

    // 3. Find the playlist
    const playlist = user.playlists.find((pl) => pl.name === playlistTitle);
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });

    // 4. Check if the track already exists in the playlist
    const alreadyExists = playlist.tracks.includes(track._id);
    if (alreadyExists) {
      return res.status(400).json({ error: "Track already in playlist" });
    }

    playlist.tracks.push(track._id);

    // Saviing the user document
    await user.save();

    res
      .status(200)
      .json({ message: "Track added to playlist successfully", playlist });
  } catch (error) {
    console.error("Error adding track to playlist:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Remoce From Playlist
app.post("/remove-from-playlist", async (req, res) => {
  const authHeader = req.headers.authorization;
  const { playlistName, trackId } = req.body;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64").toString()
  );
  const email = decoded?.email;

  if (!email) {
    return res.status(400).json({ error: "Invalid token" });
  }

  if (!playlistName || !trackId) {
    return res.status(400).json({ error: "PlaylistName & trackId is missing" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Find the playlist
    const playlist = user.playlists.find((pl) => pl.name === playlistName);
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });

    // Check if track exists in playlist
    const trackIndex = playlist.tracks.findIndex(
      (id) => id.toString() === trackId
    );
    if (trackIndex === -1) {
      return res.status(404).json({ error: "Track not found in playlist" });
    }

    // Remove the track from playlist
    playlist.tracks.splice(trackIndex, 1);

    // Save the updated user document
    await user.save();

    res.status(200).json({
      message: "Track removed from playlist successfully",
      playlist,
    });
  } catch (error) {
    console.error("Error removing track from playlist:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// like endpoint
app.post("/toggle-like", async (req, res) => {
  const authHeader = req.headers.authorization;
  const { trackId } = req.body;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64").toString()
  );
  const email = decoded?.email;

  if (!email) {
    return res.status(400).json({ error: "Invalid token" });
  }

  if (!trackId) {
    return res.status(400).json({ error: "trackId is required" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    const isLiked = user.likedTracks.includes(trackId);

    if (isLiked) {
      // If already liked, unlike it (remove from likedTracks)
      user.likedTracks = user.likedTracks.filter(
        (id) => id.toString() !== trackId
      );
    } else {
      // If not liked, like it (add to likedTracks)
      user.likedTracks.push(trackId);
    }

    await user.save();

    res.status(200).json({
      message: isLiked
        ? "Track unliked successfully"
        : "Track liked successfully",
      likedTracks: user.likedTracks,
    });
  } catch (error) {
    console.error("Error toggling like:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// get like songs
app.get("/liked-tracks", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  const decoded = JSON.parse(
    Buffer.from(token.split(".")[1], "base64").toString()
  );
  const email = decoded?.email;

  if (!email) {
    return res.status(400).json({ error: "Invalid token" });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) return res.status(404).json({ error: "User not found" });

    // Fetch full track documents
    const likedTrackDocs = await Track.find({
      _id: { $in: user.likedTracks },
    });

    res.status(200).json({ likedTracks: likedTrackDocs });
  } catch (error) {
    console.error("Error fetching liked track documents:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
