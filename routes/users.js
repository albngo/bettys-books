// Create a new router
const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const saltRounds = 10;

// Route for registration
router.get('/register', function (req, res, next) {
    res.render('register.ejs');
});    

router.post('/registered', function (req, res, next) {
    const plainPassword = req.body.password;
    const userName = req.body.username;
    const firstName = req.body.first;
    const lastName = req.body.last;
    const email = req.body.email;

    bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
        if (err) {
            return next(err); // Handle error
        }

        // Store hashed password in your database.
        const sql = 'INSERT INTO users (username, first_name, last_name, email, hashedPassword) VALUES (?, ?, ?, ?, ?)';

        db.query(sql, [userName, firstName, lastName, email, hashedPassword], function(err, result) {
            if (err) {
                return next(err); // Handle error
            }

            // Prepare response output
            let resultResponse = 'Hello ' + firstName + ' ' + lastName + 
                ', you are now registered! We will send an email to you at ' + email;

            // Sending the response
            res.send(resultResponse);
        });
    });
});

// Route for login
router.get('/login', function (req, res, next) {
    res.render('login.ejs');
});

// Route to handle login logic
router.post('/loggedin', function (req, res, next) {
    const userName = req.body.username;
    const password = req.body.password;

    // Select the hashed password for the user from the database
    const sql = 'SELECT hashedPassword FROM users WHERE username = ?';
    db.query(sql, [userName], function(err, results) {
        if (err) {
            return next(err); // Handle error
        }

        // Check if user exists
        if (results.length > 0) {
            const hashedPassword = results[0].hashedPassword;

            // Compare the password supplied with the password in the database
            bcrypt.compare(password, hashedPassword, function(err, result) {
                if (err) {
                    return next(err); // Handle error
                }

                if (result === true) {
                    // Send a success message
                    res.send('Login successful! Welcome back, ' + userName + '!');
                } else {
                    // Send a failure message
                    res.send('Login failed! Incorrect username or password.');
                }
            });
        } else {
            // User does not exist
            res.send('Login failed! Incorrect username or password.');
        }
    });
});

// Export the router object so index.js can access it
module.exports = router;
