import * as jose from 'jose';
import * as oidc from "oidc-provider";
import express from "express";
import z from "zod";
import { readFile } from "fs/promises";

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const ISSUER = process.env.ISSUER ?? `http://localhost:${PORT}`;
const PRIVATE_KEY_PATH = process.env.PRIVATE_KEY_PATH;

async function generateJwks() {
  const privateKeyPem = await readFile(PRIVATE_KEY_PATH, 'utf8');
  const cryptoKey = await jose.importPKCS8(privateKeyPem, 'RS256', { extractable: true });
  const exportedJwk = await jose.exportJWK(cryptoKey);
  const thumbprint = await jose.calculateJwkThumbprint(exportedJwk);
  const jwk = {
    ...exportedJwk,
    kid: thumbprint,
    use: 'sig',
    alg: 'RS256',
  };
  return {
    keys: [jwk],
  }
}

const jwks = await generateJwks();

const accountId = crypto.randomUUID();
const email = `${accountId}@local`;
const fullName = `${accountId.toUpperCase()}`;


const provider = new oidc.Provider(ISSUER, {
  jwks,
  features: {
    devInteractions: {
      enabled: false,
    },
  },
  claims: {
    openid: [
      'sub',
      'email',
      'name',
    ],
  },
  clients: [
    {
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uris: ["http://localhost:3000/api/auth/oidc/gitlab/redirect"],
    },
  ],
  async findAccount(ctx, sub) {
    return {
      accountId,
      claims() {
        return {
          sub,
          email,
          name: fullName,
        }
      },
    }
  },
  interactions: {
    url(ctx, interaction) {
      return `/oidc/interaction/${interaction.uid}`;
    },
  },
});

const app = express();

app.get("/oidc/interaction/:uid", async (req, res, next) => {
  try {
    const { params } = await provider.interactionDetails(req, res);
    const clientId = z.string().parse(params.client_id);
    const grant = new provider.Grant({
      accountId,
      clientId,
    });
    grant.addOIDCScope('openid');
    const grantId = await grant.save();
    const result = {
      login: { accountId },
      consent: {
        grantId,
      }
    };
    return await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
  } catch (err) {
    next(err);
  }
});

app.use("/oidc", provider.callback());

app.listen(PORT, () => {
  console.log(`OIDC provider listening on port ${PORT}`);
});
