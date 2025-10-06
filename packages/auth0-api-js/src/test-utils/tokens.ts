import * as jose from 'jose';

const rs256Jwk = {
  kty: 'RSA',
  n: 'whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw',
  e: 'AQAB',
  d: 'VuVE_KEP6323WjpbBdAIv7HGahGrgGANvbxZsIhm34lsVOPK0XDegZkhAybMZHjRhp-gwVxX5ChC-J3cUpOBH5FNxElgW6HizD2Jcq6t6LoLYgPSrfEHm71iHg8JsgrqfUnGYFzMJmv88C6WdCtpgG_qJV1K00_Ly1G1QKoBffEs-v4fAMJrCbUdCz1qWto-PU-HLMEo-krfEpGgcmtZeRlDADh8cETMQlgQfQX2VWq_aAP4a1SXmo-j0cvRU4W5Fj0RVwNesIpetX2ZFz4p_JmB5sWFEj_fC7h5z2lq-6Bme2T3BHtXkIxoBW0_pYVnASC8P2puO5FnVxDmWuHDYQ',
  p: '07rgXd_tLUhVRF_g1OaqRZh5uZ8hiLWUSU0vu9coOaQcatSqjQlIwLW8UdKv_38GrmpIfgcEVQjzq6rFBowUm9zWBO9Eq6enpasYJBOeD8EMeDK-nsST57HjPVOCvoVC5ZX-cozPXna3iRNZ1TVYBY3smn0IaxysIK-zxESf4pM',
  q: '6qrE9TPhCS5iNR7QrKThunLu6t4H_8CkYRPLbvOIt2MgZyPLiZCsvdkTVSOX76QQEXt7Y0nTNua69q3K3Jhf-YOkPSJsWTxgrfOnjoDvRKzbW3OExIMm7D99fVBODuNWinjYgUwGSqGAsb_3TKhtI-Gr5ls3fn6B6oEjVL0dpmk',
  dp: 'mHqjrFdgelT2OyiFRS3dAAPf3cLxJoAGC4gP0UoQyPocEP-Y17sQ7t-ygIanguubBy65iDFLeGXa_g0cmSt2iAzRAHrDzI8P1-pQl2KdWSEg9ssspjBRh_F_AiJLLSPRWn_b3-jySkhawtfxwO8Kte1QsK1My765Y0zFvJnjPws',
  dq: 'KmjaV4YcsVAUp4z-IXVa5htHWmLuByaFjpXJOjABEUN0467wZdgjn9vPRp-8Ia8AyGgMkJES_uUL_PDDrMJM9gb4c6P4-NeUkVtreLGMjFjA-_IQmIMrUZ7XywHsWXx0c2oLlrJqoKo3W-hZhR0bPFTYgDUT_mRWjk7wV6wl46E',
  qi: 'iYltkV_4PmQDfZfGFpzn2UtYEKyhy-9t3Vy8Mw2VHLAADKGwJvVK5ficQAr2atIF1-agXY2bd6KV-w52zR8rmZfTr0gobzYIyqHczOm13t7uXJv2WygY7QEC2OGjdxa2Fr9RnvS99ozMa5nomZBqTqT7z5QV33czjPRCjvg6FcE',
};

const ps256Jwk = {
  kty: 'RSA',
  n: 'nO67sOldeKRh6E_-P4CtrnnWQLCt3WMEDCL4GZ7sUHV57TTMrq9-2ytPFuBWerjpC78jVN71guHICQUzA5QEajsfJaRCJ6jCXVrblJ3B-HdGckd0APR_J1aH2dq5ntXGjjONhE0XA9470a_41lvjMsPKi8NkGV8qhHs-x95reTeEUvAK43hJ3dHPF054X_myulAcdw-RkqJlZzIy3AuYqQ3OP_GF9S9AQhHfOlOf0f5lgVLhSBjgk03LyljwH_JOh7s-bKYf_YJIjVmlp8aVSqYFi6OOz0ICwG_jUWP7iMiCapZKU3vN5l3wMiaaH5U26I5Xq50snWjv-k7O0eHI5w',
  e: 'AQAB',
  d: 'HZCCLo2ATPqW8Vekm90Hm1-bo_tE_fip6glqeRUuCuhezHfOebhZKzwI_dPMpvkP-mULaHFKilozv7NJjYqEnGi_8Oz1g5gw6bp0tJZV1RPPYzcf3RAypjwQgtPIdWprqh1_MyX8yH9FALdopyWPc2BcV6E7SeZaUbQQO0IlOCQYBEAj40Y7-_Tx0QbU0C8e6Ug1NXyrzt7yJrFJWPHEZvAB4pUo6BA7WDVGNpplKm2O7MieMyJAnE4dt3imoSpZw0rZmsx3DG0kbHyqM4vYZqjBpdvyNtrEG3UH6BMy9Z0GUWUR3GoUT_7O69nYik1gJwGgtRsJvDrlCwWaC1CurQ',
  p: '27LNTNZA2sqCSDGeLgesN96DnF7c9C9Y0znPdaFSRLCOBqq91kLEsXguWUuhSQDPOsg1vKkSUXdIKdQzzl-XCB8MW7M_ENmTZXNuNtZ3y1TS8zgokrtT2quj62OiioFxft5hUup9R-z-6AwVCw_fS8c4-Y1OdDEtmX8D3eJCkNM',
  q: 'ttzydX4aiOrL8yHuFTj2sXRx0_uWH960d8d8mCv9VztusAbDtY9p0C_Wo2Nzd1fR4odG_GFkmIg7NeFnHiBrotnsRcqJzZxgaYq200MZMOWt6KWo_kekkffjy53c6geJhlqMwGQiGWf08eMEhN4C8CvRwrUi6_v2JAaQbo72ex0',
  dp: 'cYdCA7SrquP-0uOhA9Q_MFex1vpGX4Cf-_bht713T7uUiOluU-wIzFR4TviADcN3Ur7m1ejgaGylQ8g-RSSsXSv-LNzBeCmWu1Qc3gWRvebFY53fiYN334XWnOrNsZkWVyL_U-OMfcCAMNUdgqvfDb-TN5HHus826xzxmJU1JLU',
  dq: 'T9yjD2kpkY5p0B-LaT1dkBa498mywOx0iLNY2OStWgGcz8fEhXDC16ds6CKw9Pgns_U8rVCjrHIi2d89N80U9SSTqc9Q67lV6gIo4o81W0OT9j0TVypW12EZ3X1uU89C4qh9PDD_K3VZZqKtAJItWlLo405UmBeMYiNzxLUvNIk',
  qi: 'qSsBIedYfYJD78MNHvWgZdl8dZpW3IkpOhGae-CvbV-9Nav0ZD-FaxkNNKZioq8AgXoW9urR3AS_G-ZrBmlaRP6kMhN_sAejAUBEg0aYkB0J2yuUdQODq9Bz3ol1gHtno9ytFeYI4xYAB1xI8TxuxRm78Ww6mebVUsrLE5oOf8w',
};

export const generateToken = async (
  domain: string,
  userId: string,
  audience?: string,
  issuer?: string | false,
  issuedAt?: number | false,
  expiresAt?: number | false,
  claims?: { [key: string]: unknown },
  algorithm: 'RS256' | 'PS256' = 'RS256'
) => {
  const jwk = algorithm === 'PS256' ? ps256Jwk : rs256Jwk;
  const kid = algorithm === 'PS256' ? 'ps256-key' : 'rs256-key';
  const privateKey = await jose.importJWK(jwk, algorithm);
  let jwtBuilder = new jose.SignJWT({ 'urn:example:claim': true, ...claims }).setProtectedHeader({ alg: algorithm, kid });

  if (issuedAt !== false) {
    jwtBuilder = jwtBuilder.setIssuedAt(issuedAt);
  }

  if (expiresAt !== false) {
    jwtBuilder = jwtBuilder.setExpirationTime(expiresAt ?? '2h');
  }


  if (issuer !== false) {
    jwtBuilder = jwtBuilder.setIssuer(issuer ?? `https://${domain}/`);
  }

  if (audience) {
    jwtBuilder = jwtBuilder.setAudience(audience);
  }
  return await jwtBuilder.setSubject(userId).sign(privateKey);
};

export const jwks = [
  {
    kty: 'RSA',
    kid: 'rs256-key',
    n: 'whYOFK2Ocbbpb_zVypi9SeKiNUqKQH0zTKN1-6fpCTu6ZalGI82s7XK3tan4dJt90ptUPKD2zvxqTzFNfx4HHHsrYCf2-FMLn1VTJfQazA2BvJqAwcpW1bqRUEty8tS_Yv4hRvWfQPcc2Gc3-_fQOOW57zVy-rNoJc744kb30NjQxdGp03J2S3GLQu7oKtSDDPooQHD38PEMNnITf0pj-KgDPjymkMGoJlO3aKppsjfbt_AH6GGdRghYRLOUwQU-h-ofWHR3lbYiKtXPn5dN24kiHy61e3VAQ9_YAZlwXC_99GGtw_NpghFAuM4P1JDn0DppJldy3PGFC0GfBCZASw',
    e: 'AQAB',
  },
  {
    kty: 'RSA',
    kid: 'ps256-key',
    n: 'nO67sOldeKRh6E_-P4CtrnnWQLCt3WMEDCL4GZ7sUHV57TTMrq9-2ytPFuBWerjpC78jVN71guHICQUzA5QEajsfJaRCJ6jCXVrblJ3B-HdGckd0APR_J1aH2dq5ntXGjjONhE0XA9470a_41lvjMsPKi8NkGV8qhHs-x95reTeEUvAK43hJ3dHPF054X_myulAcdw-RkqJlZzIy3AuYqQ3OP_GF9S9AQhHfOlOf0f5lgVLhSBjgk03LyljwH_JOh7s-bKYf_YJIjVmlp8aVSqYFi6OOz0ICwG_jUWP7iMiCapZKU3vN5l3wMiaaH5U26I5Xq50snWjv-k7O0eHI5w',
    e: 'AQAB',
  },
];
