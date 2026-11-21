const MIN_ENTROPY = 60; const MIN_LENGTH = 12;
const PATTERNS: [RegExp, string][] = [
  [/.{1,10}123456.{1,10}/i, "séquence numérique 123456"],
  [/.{1,10}password.{1,10}/i, "mot de passe en clair"],
  [/.{1,10}qwerty.{1,10}/i, "motif clavier qwerty"],
  [/.{1,10}admin.{1,10}/i, "identifiant admin"],
  [/.{1,10}welcome.{1,10}/i, "mot de bienvenue"],
  [/.{1,10}abc123.{1,10}/i, "motif alphanumérique abc123"],
  [/.{1,10}letmein.{1,10}/i, "expression d'accès"],
];
function entropy(pw: string): number {
  if (!pw) return 0;
  const hasLower = /[a-z]/.test(pw), hasUpper = /[A-Z]/.test(pw), hasDigit = /[0-9]/.test(pw), hasSpecial = /[^a-zA-Z0-9]/.test(pw);
  let cs = 94;
  if (hasLower && hasUpper && hasDigit && hasSpecial) cs = 94;
  else if (hasLower && hasUpper && hasDigit) cs = 62;
  else if (hasLower && hasDigit) cs = 36;
  else if (hasLower) cs = 26;
  return pw.length * Math.log2(cs);
}
export function analyzePassword(password: string) {
  const len = password.length;
  const ent = entropy(password);
  const patterns = PATTERNS.filter(([re]) => re.test(password)).map(([, d]) => d);
  let level: "très fort"|"fort"|"moyen"|"faible";
  let rec: string;
  if (len >= MIN_LENGTH && ent >= MIN_ENTROPY && !patterns.length) { level = "très fort"; rec = "Ce mot de passe est très sécurisé."; }
  else if (len >= MIN_LENGTH && ent >= MIN_ENTROPY - 15) { level = "fort"; rec = "Ce mot de passe est solide."; }
  else if (len >= MIN_LENGTH - 3 && ent >= 30) { level = "moyen"; rec = "Ce mot de passe est acceptable mais pourrait être renforcé."; }
  else { level = "faible"; rec = "Ce mot de passe est trop faible. Remplacez-le immédiatement."; }
  const reasons: string[] = [];
  if (len < MIN_LENGTH) reasons.push("Trop court (" + len + " < " + MIN_LENGTH + " caractères recommandés)");
  if (ent < MIN_ENTROPY) reasons.push("Entropie faible (" + ent.toFixed(1) + " bits < " + MIN_ENTROPY + " bits recommandés)");
  if (patterns.length) reasons.push("Contient des patterns courants: " + patterns.slice(0,3).join(", "));
  else reasons.push("Aucun pattern courant détecté (positif)");
  return {
    password: password.length > 4 ? "****" + password.slice(-4) : "****",
    length: len, entropy: Math.round(ent * 100) / 100, level, common_patterns: patterns,
    reasons, recommendation: rec,
  };
}