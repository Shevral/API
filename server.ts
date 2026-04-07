const app = require("express")();
const httpServer = require("http").Server(app);

const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ObjectId = require("mongodb").ObjectID;
const connection = mongoose.connection;
const randomString = require("randomstring");
const cors = require("cors");
const colors = require("colors");
const mongodb = require("./config/mongodb.js");
const configFile = require("./config/config.js");
const config = configFile.config;
const bcrypt = require("bcryptjs");

const host = "api.intype.pl"; // najlepiej 0.0.0.0, żeby serwer był dostępny z zewnątrz
const port = 5000;
const date = new Date().toLocaleString("pl-PL", { timeZone: "Europe/Warsaw" });

// Middleware Express
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.set("json spaces", 4);

// Middleware do wymuszenia HTTPS
app.use((req, res, next) => {
  // jeśli połączenie nie jest HTTPS
  if (
    req.headers["x-forwarded-proto"] &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    const hostHeader = req.headers.host;
    return res.redirect(301, `https://${hostHeader}${req.url}`);
  }
  next();
});

// Twoje endpointy
app.get("/", (req, res) => {
  res.send("Hello HTTPS world!");
});

// Uruchomienie serwera Express
httpServer.listen(port, host, () => {
  console.log(
    colors.cyan(`
    ████████╗ █████╗ ██████╗ ███████╗████████╗███████╗ ██████╗ ██    ██╗
    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗╚██╗ ██╔╝
       ██║   ███████║██████╔╝███████╗   ██║   ██║   ██║██████╔╝ ╚████╔╝ 
       ██║   ██╔══██║██╔════╗╚════██║   ██║   ██║   ██║██╔══██╗  ╚██╔╝  
       ██║   ██║  ██║██║    ║███████║   ██║   ╗╚████╔╝ ██║  ██║   ██║   
       ╚═╝   ╚═╝  ╚═╝╚═╝    ╚══════╝    ╚═╝   ╚═════╝  ╚═╝  ╚═╝   ╚═╝   
    `)
  );

  console.log(colors.yellow("🚀 TapStory server is starting..."));
  console.log(colors.red("--------------------------------"));
  console.log(colors.red("Server has started at"), colors.blue(date));
  console.log("Server host: ", colors.green(host + ":" + port));
  console.log(
    "Server status: ",
    colors.green("Running (HTTPS enforced via proxy)")
  );
});

app.post("/register", async (req, res) => {
  try {
    const { email, psw } = req.body;
    const pswCrypted = bcrypt.hashSync(psw, 10);

    if (!email || !psw) {
      return res.json({
        error: true,
        signed: false,
        msg: "Empty email or password value",
      });
    }

    const UsersCollection = connection.db.collection("Accounts");
    const user = await UsersCollection.findOne({ email });

    if (user) {
      return res.json({
        error: true,
        signed: false,
        msg: "Email juz istnieje w bazie danych",
      });
    }

    if (!user) {
      const newUser = {
        name: "John Doe",
        email: email,
        psw: pswCrypted,
        followers: 0,
        publications: 0,
        bio: "lorem ipsum",
        shelf: [],
        library: [],
        books: [],
        handshake: {
          hash: randomString.generate(),
        },
        createdAt: new Date(),
        avatar: "",
      };

      const result = await UsersCollection.insertOne(newUser);
      console.log("Inserted ID:", result.insertedId);

      return res.json({
        error: false,
        signed: true,
        msg: "Signed complete",
      });
    }
  } catch (err) {
    console.error("Auth error:", err);
    return res.json({
      error: true,
      signed: false,
      msg: "Internal server error",
    });
  }
});

app.post("/auth", async (req, res) => {
  try {
    const { email, psw } = req.body;

    if (!email || !psw) {
      return res.json({
        error: true,
        auth: false,
        msg: "Empty login or password value",
      });
    }

    const UsersCollection = connection.db.collection("Accounts");
    const user = await UsersCollection.findOne({ email });

    if (!user) {
      return res.json({
        error: true,
        auth: false,
        msg: "Incorrect email or password",
      });
    }

    // porównanie hasła
    const isMatch = await bcrypt.compare(psw, user.psw);
    if (!isMatch) {
      return res.json({
        error: true,
        auth: false,
        msg: "Incorrect email or password",
      });
    }

    // handshake (token sesyjny)
    const date = new Date().toLocaleString("pl-PL", {
      timeZone: "Europe/Warsaw",
    });
    const handshake = randomString.generate();

    await UsersCollection.updateOne({ _id: user._id }, { $set: { handshake } });

    console.log(
      colors.grey(date),
      "|",
      "Account",
      colors.blue(user._id),
      "has logged in."
    );

    return res.json({
      error: false,
      auth: true,
      id: user._id,
      data: user,
      handshake: handshake,
      msg: "OK",
    });
  } catch (err) {
    console.error("Auth error:", err);
    return res.json({
      error: true,
      auth: false,
      msg: "Internal server error",
    });
  }
});

app.post("/handshake", async (req, res) => {
  try {
    const { handshake } = req.body;

    if (!handshake) {
      return res.json({
        error: true,
        auth: false,
        message: "Handshake not exist",
      });
    }

    const UsersCollection = connection.db.collection("Accounts");
    const user = await UsersCollection.findOne({ handshake });

    if (!user) {
      return res.json({
        error: true,
        auth: false,
        message: "Invalid handshake",
      });
    }

    return res.json({
      error: false,
      auth: true,
      id: user._id,
      data: user,
      handshake: handshake,
      msg: "User logged in",
    });
  } catch (err) {
    console.error("Auth error:", err);
    return res.json({
      error: true,
      auth: false,
      msg: "Internal server error",
    });
  }
});

app.post("/auth_storage/:id?/:handshake?", (req, res) => {
  if (!req.query.id || !req.query.handshake) {
    return res.json({
      error: true,
      auth: false,
      msg: "Empty login or password value",
    });
  } else {
    connection.db.collection("Accounts", (err, UsersCollection) => {
      UsersCollection.find({
        _id: new ObjectId(req.query.id),
        handshake: req.query.handshake,
      }).toArray((err, data) => {
        if (err) {
          return res.json({ error: true, auth: false, msg: err });
        } else {
          if (!data[0]) {
            return res.json({
              error: true,
              auth: false,
              msg: "no logged-redirect to login page",
            });
          } else {
            let date = new Date().toLocaleString("pl-PL", {
              timeZone: "Europe/Warsaw",
            });
            let handshake = randomString.generate();
            UsersCollection.updateOne({ _id: data[0]._id }, [
              { $set: { handshake: handshake } },
            ]);
            console.log(
              colors.grey(date),
              "|",
              "Account",
              colors.blue(data[0]._id),
              "has logged in from local storage."
            );
            return res.json({
              error: false,
              auth: true,
              id: data[0]._id,
              handshake: handshake,
              msg: "OK",
            });
          }
        }
      });
    });
  }
});

app.post("/user", async (req, res) => {
  try {
    const { id } = req.query;

    if (!id) {
      console.log("Niepowodzenie pobrania danych usera");
      return res.json({
        error: true,
        msg: "Bad request",
      });
    }

    const UsersCollection = connection.db.collection("Accounts");
    const user = await UsersCollection.findOne({ _id: new ObjectId(id) });

    if (!user) {
      return res.json({
        error: true,
        msg: "No data",
      });
    }

    return res.json({
      error: false,
      res: user.data, // uwaga: tu zwracasz tylko pole "data"
    });
  } catch (err) {
    console.error("User fetch error:", err);
    return res.json({
      error: true,
      msg: "Internal server error",
    });
  }
});

app.post("/book", async (req, res) => {
  try {
    const { id } = req.body;

    const objectId = new ObjectId(id);

    if (!id) {
      console.log("Niepowodzenie pobrania danych książki:", id);
      return res.json({
        error: true,
        msg: "Bad request",
      });
    }

    const BooksCollection = connection.db.collection("Books");
    const book = await BooksCollection.findOne({ _id: objectId });

    if (!book) {
      return res.json({
        error: true,
        msg: "No data",
        id,
      });
    }

    return res.json({
      error: false,
      res: book,
    });
  } catch (err) {
    console.error("Book fetch error:", err);
    return res.json({
      error: true,
      msg: "Internal server error",
    });
  }
});

app.post("/books/", (req, res) => {
  connection.db.collection("Books", (err, BooksCollection) => {
    BooksCollection.find().toArray((err, data) => {
      if (err) {
        return res.json({ error: true, msg: err });
      } else {
        if (!data[0]) {
          return res.json({
            error: true,
            msg: "No data",
          });
        } else {
          return res.json({
            error: false,
            res: data,
          });
        }
      }
    });
  });
});

app.post("/publishBook/:data?", (req, res) => {
  if (!req.body.data) {
    console.log("Niepowodzenie pobrania danych ksiazki " + req.body.data);
    return res.json({
      error: true,
      msg: "Bad request",
    });
  } else {
    //Dodanie nowej ksiazki do bazy mongodb
    //Sprawdzic czy ksiazka juz taka istnieje w bazie
    connection.db.collection("Books", (err, BooksCollection) => {
      BooksCollection.insertOne(req.body.data);
      if (err) {
        console.log(err);
        return;
      } else {
        console.log(
          "Książka " + req.body.data.metadata.title + " została opublikowana"
        );
        return res.json({
          error: false,
          msg:
            "Książka " + req.body.data.metadata.title + " została opublikowana",
        });
      }
    });
  }
});

app.patch("/addBookToShelf", async (req, res) => {
  const { userId, bookId } = req.body;

  if (!userId || !bookId) {
    return res.status(400).json({ error: "userId i bookId są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    const result = await AccountsCollection.findOneAndUpdate(
      { _id: new ObjectId(userId) }, // pamiętaj o konwersji do ObjectId
      { $addToSet: { shelf: { id: bookId.id } } }, // dodajemy obiekt
      { returnDocument: "after" } // żeby zwrócić aktualny dokument
    );

    if (!result.value) {
      return res.status(404).json({ error: "Użytkownik nie znaleziony" });
    }

    res.json(result.value.shelf);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.patch("/removeBookFromShelf", async (req, res) => {
  const { userId, bookId } = req.body;

  if (!userId || !bookId) {
    return res.status(400).json({ error: "userId i bookId są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    const result = await AccountsCollection.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      { $pull: { shelf: { id: bookId.id } } }, // 🔥 usuwa obiekt z półki
      { returnDocument: "after" }
    );

    if (!result.value) {
      return res.status(404).json({ error: "Użytkownik nie znaleziony" });
    }

    res.json(result.value.shelf);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.patch("/updateProgress", async (req, res) => {
  let { userId, bookId, progress } = req.body;

  // Normalizacja bookId — na wypadek, gdyby frontend wysłał obiekt { id: "..." }
  if (typeof bookId === "object" && bookId !== null && bookId.id) {
    bookId = bookId.id;
  }

  if (!userId || !bookId || progress === undefined) {
    return res
      .status(400)
      .json({ error: "userId, bookId i progress są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    // Spróbuj zaktualizować istniejącą książkę po ID (string)
    const result = await AccountsCollection.findOneAndUpdate(
      {
        _id: new ObjectId(userId),
        "library.id": bookId,
      },
      {
        $set: { "library.$.progress": progress },
      },
      { returnDocument: "after" }
    );

    if (result.value) {
      // ✅ Książka już istniała – progress zaktualizowany
      return res.json({
        message: "Progress zaktualizowany",
        library: result.value.library,
      });
    }

    // ❌ Książka nie istniała – dodajemy nową
    const addResult = await AccountsCollection.findOneAndUpdate(
      { _id: new ObjectId(userId) },
      {
        $push: {
          library: {
            id: bookId, // <-- teraz to ZAWSZE string
            progress: progress,
          },
        },
      },
      { returnDocument: "after" }
    );

    if (!addResult.value) {
      return res.status(404).json({ error: "Użytkownik nie znaleziony" });
    }

    res.json({
      message: "Nowa książka dodana z postępem",
      library: addResult.value.library,
    });
  } catch (err) {
    console.error("Błąd updateProgress:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/addBook", async (req, res) => {
  console.log("run add");
  const { userId, book } = req.body;

  // jeśli książka jest opakowana jako book.book — rozpakuj ją:
  const realBook = book.book ? book.book : book;

  if (!userId || !realBook) {
    return res.status(400).json({ error: true, msg: "Brak danych" });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      { $push: { books: realBook } }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ error: true, msg: "Nie znaleziono użytkownika" });
    }

    console.log(`✅ Książka "${realBook.metadata?.title}" została dodana.`);
    res.json({ error: false, msg: "Książka dodana pomyślnie" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, msg: "Błąd serwera" });
  }
});

app.patch("/bookTitleUpdate", async (req, res) => {
  console.log("bookupdate title run");
  let { userId, bookId, newTitle } = req.body;

  // Normalizacja bookId jeśli przyszło jako obiekt
  if (typeof bookId === "object" && bookId !== null && bookId.id) {
    bookId = bookId.id;
  }

  if (!userId || !bookId || !newTitle) {
    return res
      .status(400)
      .json({ error: "userId, bookId i newTitle są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    // Aktualizacja tytułu książki
    const updateResult = await AccountsCollection.findOneAndUpdate(
      {
        _id: new ObjectId(userId),
        "books.id": bookId,
      },
      {
        $set: { "books.$.metadata.title": newTitle },
      },
      { returnDocument: "after" }
    );

    if (!updateResult.value) {
      return res.status(404).json({
        error: "Użytkownik lub książka nie znaleziony",
      });
    }

    res.json({
      message: "Tytuł zaktualizowany",
      books: updateResult.value.books,
    });
  } catch (err) {
    console.error("Błąd bookTitleUpdate:", err);
    res.status(500).json({ error: err.message });
  }
});
app.patch("/bookGenreUpdate", async (req, res) => {
  console.log("bookupdate genre run");
  let { userId, bookId, newGenre } = req.body;

  // Normalizacja bookId jeśli przyszło jako obiekt
  if (typeof bookId === "object" && bookId !== null && bookId.id) {
    bookId = bookId.id;
  }

  if (!userId || !bookId || !newGenre) {
    return res
      .status(400)
      .json({ error: "userId, bookId i newGenre są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    // Aktualizacja tytułu książki
    const updateResult = await AccountsCollection.findOneAndUpdate(
      {
        _id: new ObjectId(userId),
        "books.id": bookId,
      },
      {
        $set: { "books.$.metadata.genre": newGenre },
      },
      { returnDocument: "after" }
    );

    if (!updateResult.value) {
      return res.status(404).json({
        error: "Użytkownik lub książka nie znaleziony",
      });
    }

    res.json({
      message: "Kategorie zaktualizowany",
      books: updateResult.value.books,
    });
  } catch (err) {
    console.error("Błąd bookGenreUpdate:", err);
    res.status(500).json({ error: err.message });
  }
});
app.patch("/bookDescriptionUpdate", async (req, res) => {
  console.log("bookupdate desc run");
  let { userId, bookId, newDescription } = req.body;

  // Normalizacja bookId jeśli przyszło jako obiekt
  if (typeof bookId === "object" && bookId !== null && bookId.id) {
    bookId = bookId.id;
  }

  if (!userId || !bookId || !newDescription) {
    return res
      .status(400)
      .json({ error: "userId, bookId i newDescription są wymagane" });
  }

  const AccountsCollection = connection.db.collection("Accounts");

  try {
    // Aktualizacja tytułu książki
    const updateResult = await AccountsCollection.findOneAndUpdate(
      {
        _id: new ObjectId(userId),
        "books.id": bookId,
      },
      {
        $set: { "books.$.metadata.shortDesc": newDescription },
      },
      { returnDocument: "after" }
    );

    if (!updateResult.value) {
      return res.status(404).json({
        error: "Użytkownik lub książka nie znaleziony",
      });
    }

    res.json({
      message: "Opis zaktualizowany",
      books: updateResult.value.books,
    });
  } catch (err) {
    console.error("Błąd bookDescriptionUpdate:", err);
    res.status(500).json({ error: err.message });
  }
});

// Usuń książkę
app.post("/deleteBook", async (req, res) => {
  console.log("delete book run");

  const { userId, bookId } = req.body;

  if (!userId || !bookId) {
    return res.status(400).json({ error: true, msg: "Brak danych" });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      {
        $pull: {
          books: { id: bookId },
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({
        error: true,
        msg: "Nie znaleziono książki lub użytkownika",
      });
    }

    return res.json({
      error: false,
      msg: "Książka usunięta",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: true,
      msg: "Błąd serwera",
    });
  }
});

// Usuń scenę
app.post("/deleteScene", async (req, res) => {
  console.log("delete scene run");

  const { userId, bookId, sceneId } = req.body;

  if (!userId || !bookId || !sceneId) {
    return res.status(400).json({
      error: true,
      msg: "Brak danych",
    });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    const result = await Accounts.updateOne(
      {
        _id: new ObjectId(userId),
        "books.id": bookId,
      },
      {
        $pull: {
          "books.$.scenes": { id: sceneId },
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({
        error: true,
        msg: "Nie znaleziono sceny / książki / użytkownika",
      });
    }

    return res.json({
      error: false,
      msg: "Scena usunięta",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: true,
      msg: "Błąd serwera",
    });
  }
});

// Usuń opcję
app.post("/deleteOption", async (req, res) => {
  console.log("delete option run"); // już się wywołuje

  const { userId, bookId, sceneId, optionId } = req.body;

  if (!userId || !bookId || !sceneId || !optionId) {
    return res.status(400).json({ error: true, msg: "Brak danych" });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    console.log("userid:" + userId);
    console.log("bookid:" + bookId);
    console.log("sceneid:" + sceneId);
    console.log("optionid:" + optionId);

    const account = await Accounts.findOne({ _id: new ObjectId(userId) });

    const book = account.books.find((b) => b.id === bookId);
    const scene = book.scenes.find((s) => s.id === sceneId);

    scene.options = scene.options.filter((o) => o.id !== optionId);

    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { books: account.books } }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ error: true, msg: "Nie znaleziono opcji / sceny / książki" });
    }

    return res.json({ error: false, msg: "Opcja usunięta" }); // MUSI być return
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: true, msg: "Błąd serwera" });
  }
});

app.post("/addScene", async (req, res) => {
  console.log("add scene");
  const { userId, bookId, scene } = req.body;

  if (!userId || !bookId || !scene) {
    return res.status(400).json({ error: true, msg: "Brak danych" });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    const result = await Accounts.updateOne(
      {
        _id: new ObjectId(userId),
        "books.id": bookId,
      },
      {
        $push: {
          "books.$.scenes": scene,
        },
      }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ error: true, msg: "Nie znaleziono użytkownika" });
    }
    console.log(userId);
    console.log(bookId);
    console.log(scene);
    res.json({ error: false, msg: "Scena dodana pomyślnie" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: true, msg: "Błąd serwera" });
  }
});

app.get("/test", (req, res) => {
  res.send("API DZIAŁA");
});
async function sceneIdExists(
  Accounts,
  userId,
  bookId,
  sceneIdToCheck,
  currentSceneId
) {
  const result = await Accounts.findOne(
    {
      _id: new ObjectId(userId),
      books: {
        $elemMatch: {
          id: bookId,
          scenes: {
            $elemMatch: {
              $and: [{ id: sceneIdToCheck }, { id: { $ne: currentSceneId } }],
            },
          },
        },
      },
    },
    { projection: { _id: 1 } }
  );

  return !!result;
}

app.patch("/updateScene", async (req, res) => {
  const { userId, bookId, sceneId, sceneData } = req.body;

  console.log("aktual;izacja sceny");

  const currentSceneId = Number(sceneId);
  const newSceneId = Number(sceneData.id);

  console.log(currentSceneId);
  console.log(newSceneId);

  if (Number.isNaN(newSceneId)) {
    return res.status(400).json({
      error: true,
      msg: "Nieprawidłowe ID sceny",
    });
  }

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    // 🔒 jeśli ID się zmienia – sprawdzamy czy wolne
    if (newSceneId !== currentSceneId) {
      const exists = await sceneIdExists(
        Accounts,
        userId,
        bookId,
        newSceneId,
        currentSceneId
      );

      if (exists) {
        return res.status(409).json({
          error: true,
          msg: "Scena o takim ID już istnieje",
        });
      }
    }

    // 🔧 wymuszamy poprawne ID
    sceneData.id = newSceneId;

    // 🧹 normalizacja content → ZAWSZE TABLICA STRINGÓW
    if (typeof sceneData.content === "string") {
      sceneData.content = [sceneData.content];
    }

    // jeśli już jest tablicą – zostaw
    if (!Array.isArray(sceneData.content)) {
      sceneData.content = [];
    }

    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      {
        $set: {
          "books.$[book].scenes.$[scene]": sceneData,
        },
      },
      {
        arrayFilters: [{ "book.id": bookId }, { "scene.id": currentSceneId }],
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        error: true,
        msg: "Nie znaleziono sceny",
      });
    }

    res.json({
      error: false,
      msg: "Scena zaktualizowana",
      sceneId: newSceneId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      msg: "Błąd serwera",
    });
  }
});

async function optionIdExists(Accounts, userId, bookId, sceneId, optionId) {
  const result = await Accounts.findOne(
    {
      _id: new ObjectId(userId),
      books: {
        $elemMatch: {
          id: bookId, // string UUID
          scenes: {
            $elemMatch: {
              id: sceneId, // number
              options: { $elemMatch: { id: optionId } },
            },
          },
        },
      },
    },
    { projection: { _id: 1 } }
  );

  return !!result;
}

app.post("/addOption", async (req, res) => {
  const { userId, bookId, sceneId, optionData } = req.body;

  // Walidacja podstawowa
  if (!userId || !bookId || !sceneId || !optionData) {
    return res.status(400).json({ error: true, msg: "Brak danych" });
  }

  const sceneIdNum = sceneId;
  const optionIdNum = optionData.id;
  const gotoNum = optionData.goto;

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    // 🔒 Sprawdzenie unikalności ID opcji
    const exists = await optionIdExists(
      Accounts,
      userId,
      bookId,
      sceneIdNum,
      optionIdNum
    );

    if (exists) {
      return res
        .status(409)
        .json({ error: true, msg: "Opcja o takim ID już istnieje" });
    }

    // Normalizacja danych
    const newOption = {
      ...optionData,
      id: optionIdNum,
      goto: gotoNum,
    };

    // Dodanie opcji do sceny
    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      { $push: { "books.$[book].scenes.$[scene].options": newOption } },
      { arrayFilters: [{ "book.id": bookId }, { "scene.id": sceneIdNum }] }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: true, msg: "Nie znaleziono sceny" });
    }

    return res.json({ error: false, msg: "Opcja dodana pomyślnie" });
  } catch (err) {
    return res.status(500).json({ error: true, msg: "Błąd serwera" });
  }
});

app.patch("/updateOption", async (req, res) => {
  console.log("update option run");
  const { userId, bookId, sceneId, optionId, sceneData } = req.body;

  const currentSceneId = sceneId;
  const newSceneId = sceneData.id;

  try {
    const db = connection.db;
    const Accounts = db.collection("Accounts");

    // 🔒 jeśli ID się zmienia – sprawdzamy czy wolne
    if (newSceneId !== currentSceneId) {
      const exists = await sceneIdExists(
        Accounts,
        userId,
        bookId,
        newSceneId,
        currentSceneId
      );

      if (exists) {
        return res.status(409).json({
          error: true,
          msg: "Scena o takim ID już istnieje",
        });
      }
    }

    // 🔧 wymuszamy poprawne ID
    sceneData.id = newSceneId;

    // 🧹 normalizacja content → ZAWSZE TABLICA STRINGÓW
    if (typeof sceneData.content === "string") {
      sceneData.content = [sceneData.content];
    }

    // jeśli już jest tablicą – zostaw
    if (!Array.isArray(sceneData.content)) {
      sceneData.content = [];
    }

    const result = await Accounts.updateOne(
      { _id: new ObjectId(userId) },
      {
        $set: {
          "books.$[book].scenes.$[scene]": sceneData,
        },
      },
      {
        arrayFilters: [{ "book.id": bookId }, { "scene.id": currentSceneId }],
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        error: true,
        msg: "Nie znaleziono sceny",
      });
    }

    res.json({
      error: false,
      msg: "Scena zaktualizowana",
      sceneId: newSceneId,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: true,
      msg: "Błąd serwera",
    });
  }
});
