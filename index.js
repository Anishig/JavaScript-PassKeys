const express = require('express');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const PORT = 3000;
const app = express();

app.use(express.static('./public'));
app.use(express.json());

const userStore = {};
const challengeStore = {};

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id,
        username,
        password
    }

    userStore[id] = user;
    console.log('Registered Successfull', userStore[id]);
    return res.json({ id });

})

app.post('/register-challenge', async(req, res) => {
    const { userId } = req.body;
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found' });
    const user = userStore[userId];
    const challengePaylod = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My Local host Machine',
        userName: user.username,
    })

    challengeStore[userId] = challengePaylod.challenge
    return res.json({ options: challengePaylod });

})


app.post('/register-verify', async(req, res) => {
    const { userId, cred } = req.body;
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found' });
    const user = userStore[userId];
    const challenge = challengeStore[userId];
    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if (!verificationResult.verified) return res.json({ error: 'could not Verify' });
    userStore[userId].passkey = verificationResult.registrationInfo
    return res.json({ verified: true });
})

app.post('/login-challenge', async(req, res) => {
    const { userId } = req.body
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found' });
    const opts = await generateAuthenticationOptions({
        rpID: 'localhost',
    })

    challengeStore[userId] = opts.challenge;
    return res.json({ options: opts });

})


app.post('/login-verify', async(req, res) => {
    const { userId, cred } = req.body;
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found' });

    const user = userStore[userId]
    const challenge = challengeStore[userId];
    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: user.passkey
    })

    if (!res.verified) return res.json({ error: 'Something Went Wrong' });
    return res.json({ success: true, userId });

})

app.listen(PORT, () => {
    console.log(`Server Started at :${PORT}`);
});