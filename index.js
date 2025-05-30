import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import axios from "axios";
import env from "dotenv";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import flash from "connect-flash";

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
env.config();

const db = process.env.DATABASE_URL
  ? new pg.Client({
      connectionString: process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false
      }
    })
:new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();
function ensureAuthenticated(req,res, next){
  if (req.isAuthenticated()){
    return next();
  }
  res.redirect("/login");
}

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
    maxAge: 1000 * 60 * 60 * 24
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req,res, next) => {
  res.locals.messages = req.flash();
  next();
});
app.use((req,res, next) => {
  res.locals.user = req.user;
  next();
});


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});


app.get("/Book-review",async (req,res) => {
  if(!req.isAuthenticated()){
    return res.redirect("/login");
  }

  try{
    const result = await db.query("SELECT books.*, reviews.id AS review_id FROM books JOIN reviews ON books.id = reviews.book_id WHERE reviews.user_id = $1 ORDER BY RANDOM() LIMIT 5",[req.user.id]);
    const books = result.rows;
    res.render("index.ejs",{
      books
    });
  } catch (err){
    console.error(err);
    res.render("index.ejs",{
      books: []
    });
  }
});

app.get("/reviewed",ensureAuthenticated, async (req,res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 6;
  const offset = (page - 1) * limit;

  try{
    const countResult = await db.query("SELECT COUNT(DISTINCT book_id) FROM reviews");
    const totalReviewed = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalReviewed / limit);

    const booksResult = await db.query("SELECT DISTINCT books.*, reviews.user_id, reviews.updated_at FROM books JOIN reviews ON books.id = reviews.book_id WHERE reviews.user_id = $1 ORDER BY reviews.updated_at DESC LIMIT $2  OFFSET $3",[req.user.id , limit, offset]);
    const books = booksResult.rows

    res.render("reviewed.ejs", {
      books,
      currentPage: page,
      totalPages
    });
  }catch(err){
    console.error("Error fetching reviewed books:", err);
    res.status(500).send("Internal Server Error")
  }
});

app.get("/search",ensureAuthenticated, async (req,res) => {
  const searchItem = req.query.q;

  try{
    const response = await axios.get(`https://openlibrary.org/search.json?q=${encodeURIComponent(searchItem)}&limit=20`);
    const data = response.data;

    const booksFromAPI = data.docs.map((doc) => {
      return{
        openlibrary_key: doc.key,
        title: doc.title,
        author: doc.author_name?doc.author_name[0] : "Unknown Author",
        cover_url: doc.cover_i? `https://covers.openlibrary.org/b/id/${doc.cover_i}-M.jpg` : "/altcover.jpeg"
      };
    });
    const olKeys = booksFromAPI.map(book => book.openlibrary_key);
    const result = await db.query(
      `SELECT DISTINCT books.openlibrary_key,reviews.user_id FROM books INNER JOIN reviews ON books.id = reviews.book_id WHERE books.openlibrary_key = ANY($1::text[]) AND reviews.user_id = $2`,[olKeys, req.user.id]
    );
    const reviewedKeys = result.rows.map(row => row.openlibrary_key);

    const finalBooks = booksFromAPI.map(book => {
  const isReviewed = reviewedKeys.includes(book.openlibrary_key);
  const reviewUrl = isReviewed
    ? `/review-by-key?key=${book.openlibrary_key}`
    : `/write-review?key=${book.openlibrary_key}`;
  
  return {
    ...book,
    isReviewed,
    reviewUrl
  };
});
    res.render("search.ejs", {books: finalBooks, query: searchItem});
  }catch (error){
    console.error("Search error:", error);
    res.status(500).send("An error occured while searching.");
  }
});

app.get("/review-by-key",ensureAuthenticated, async (req,res) => {
  const olKey = req.query.key;
  const result = await db.query("SELECT reviews.*, books.title, books.author, books.cover_url, books.openlibrary_key FROM reviews JOIN books ON reviews.book_id = books.id WHERE books.openlibrary_key = $1 AND reviews.user_id = $2",[olKey, req.user.id]);

  if(result.rows.length === 0){
    return res.status(404);
  }
  const reviewData = result.rows[0];

  res.render("read-review.ejs",
    {
      book: reviewData,
      review: reviewData
    }
  )
});

app.get("/write-review",ensureAuthenticated, async (req, res) => {
  const bookKey = req.query.key;

  if (!bookKey) return res.status(400).send("Missing key");

  res.render("review-form.ejs", {
    formTitle: "Write Review",
    formAction: `/write-review?key=${bookKey}`,
    rating: "",
    content: "",
    error: null
  });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/Book-Review",
  passport.authenticate("google", {
    successRedirect: "/Book-Review",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/Book-Review",
    failureRedirect: "/login",
    failureFlash: true
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/Book-Review");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/write-review",ensureAuthenticated, async (req, res) => {
  const olKey = req.query.key;
  const {rating, content} = req.body;

  if(!olKey) return res.status(400).send("Missing Key");

  if(rating < 1 || rating > 5) {
    return res.render("review-form.ejs",{
      formTitle: "Write Review",
      formAction: `/write-review?key=${olKey}`,
      content,
      error: "Rating should be between 1 and 5"
    });
  }
  

  try {
    let result = await db.query("SELECT id FROM books WHERE openlibrary_key = $1", [olKey]);
    let bookId;

    if(result.rows.length === 0){
      const searchResult = await axios.get(`https://openlibrary.org/search.json?q=${encodeURIComponent(olKey)}`);
      const doc = searchResult.data.docs.find(d => d.key === olKey);

      const title = doc?.title || "Unknown Title";
      const author = doc?.author_name?.[0] || "Unknown Author";
      const coverUrl = doc?.cover_i? `https://covers.openlibrary.org/b/id/${doc.cover_i}-M.jpg` : "/altcover.jpeg";

      const insertBook = await db.query("INSERT INTO books (openlibrary_key, title, author, cover_url) VALUES ($1, $2, $3, $4) RETURNING id",[olKey, title, author , coverUrl]);
      bookId = insertBook.rows[0].id;
    }else {
      bookId= result.rows[0].id;
    }

    await db.query("INSERT INTO reviews (book_id, rating, content, user_id) VALUES ($1, $2, $3, $4)", [bookId, rating, content, req.user.id]);

    res.redirect(`/review-by-key?key=${olKey}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error while submitting review");
  }
});

app.get("/edit-review",ensureAuthenticated, async (req, res) => {
  const bookKey = req.query.key;

  if (!bookKey) return res.status(400).send("Missing key");
  const reviewRow = await db.query("SELECT rating, content FROM reviews JOIN books ON reviews.book_id = books.id WHERE books.openlibrary_key = $1", [bookKey]);
  const rating = reviewRow.rows[0].rating;
  const content = reviewRow.rows[0].content;

  res.render("review-form.ejs", {
    formTitle: "Edit Review",
    formAction: `/edit-review?key=${bookKey}`,
    rating,
    content,
    error: null
  });
});

app.post("/edit-review",ensureAuthenticated, async (req, res) => {
  const olKey = req.query.key;
  const {rating, content} = req.body;

  if(!olKey) return res.status(400).send("Missing Key");

  if(rating < 1 || rating > 5) {
    return res.render("review-form.ejs",{
      formTitle: "Write Review",
      formAction: `/write-review?key=${olKey}`,
      content,
      error: "Rating should be between 1 and 5"
    });
  }
  

  try {
    let result = await db.query("SELECT id FROM books WHERE openlibrary_key = $1", [olKey]);
    if (result.rows.length === 0){
      return res.status(404).send ("Book not found");
    }
    let bookId;
    bookId= result.rows[0].id;

     await db.query("UPDATE reviews SET rating =$1, content = $2 WHERE book_id = $3 AND user_id = $4",[rating,content,bookId, req.user.id]);
     res.redirect(`/review-by-key?key=${olKey}`);
  } catch (err){
    console.error(err);
    res.status(500).send("Server error while submitting edited review");
  }
});

app.get("/delete-review",ensureAuthenticated, async (req, res) => {
  const bookKey = req.query.key;
   if (!bookKey) return res.status(400).send("Missing key");
  try{
   const result = await db.query("SELECT id FROM books WHERE books.openlibrary_key = $1",[bookKey]);
   if (result.rows.length === 0){
      return res.status(404).send ("Book not found");
    }
   let tobeBook = result.rows[0].id;

   await db.query("DELETE FROM reviews WHERE book_id = $1 AND user_id = $2 ",[tobeBook, req.user.id]);
   const remainingReviews = await db.query("SELECT COUNT(*) FROM reviews WHERE book_id = $1", [tobeBook]);
   if (parseInt(remainingReviews.rows[0].count) === 0) {
    await db.query("DELETE FROM books WHERE openlibrary_key = $1",[bookKey]);
   }
   
   res.redirect("/Book-review"); 
  }catch (err){
    console.error("Error executing query", err.stack);
    res.status(500).send("Error deleting review");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false, {message: "Invalid password"});
            }
          }
        });
      } else {
        return cb(null, false, {message: "User not found"});
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/Book-Review",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});