import { views, type View } from "./normalize";

/**
 * Rule-based prompt-injection detector.
 * Rules run on several de-obfuscated views of the text (see normalize.ts).
 * Score = sum of the strongest hit per family, times a channel multiplier;
 * hits found only in a decoded view get an obfuscation bonus.
 */

export type Family =
  | "override"
  | "jailbreak"
  | "prompt_extraction"
  | "exfiltration"
  | "delimiter"
  | "tool_abuse"
  | "addressed_to_ai"
  | "authority_claim";

export type Channel = "system" | "user" | "assistant" | "tool" | "agent";

export interface Rule {
  id: string;
  family: Family;
  weight: number;
  re: RegExp;
}

const INSTR = String.raw`(?:instructions?|rules|guidelines|directions|directives|prompts?|context|programming|constraints|guardrails|policy|policies|orders|commands)`;
const PRIOR = String.raw`(?:all|any|the|your|my|these|those|every|previous|prior|above|earlier|preceding|original|initial|system|safety|existing|old)`;

export const RULES: Rule[] = [
  // --- override ---
  { id: "ov.ignore_prior", family: "override", weight: 1, re: new RegExp(String.raw`\b(?:ignore|disregard|forget|override|bypass|skip|drop|discard|abandon|neglect)\b(?:\s+\w+){0,2}?\s+${PRIOR}\b(?:\s+\w+){0,3}?\s+${INSTR}\b`) },
  { id: "ov.ignore_above", family: "override", weight: 1, re: /\b(?:ignore|disregard|forget)\s+(?:everything|all|anything)?\s*(?:(?:you were|you've been|you have been)\s+told|(?:the|what(?:'s| is| was)?)?\s*(?:said|written|stated)?\s*(?:above|before|so far|earlier))\b/ },
  { id: "ov.ignore_question", family: "override", weight: 0.7, re: /\b(?:ignore|disregard)\s+the\s+user'?s?\s+(?:question|request|message|query)\b/ },
  { id: "ov.stop_following", family: "override", weight: 1, re: new RegExp(String.raw`\bstop\s+(?:following|obeying|using)\s+(?:\w+\s+){0,2}${INSTR}`) },
  { id: "ov.new_instructions", family: "override", weight: 0.8, re: /\b(?:new|updated|real|actual|true|revised)\s+(?:instructions?|directives?|rules|system prompt|policy)\s*(?:for (?:the |you |\w+ ){0,3})?\s*(?::|are\b|is\b|loaded\b)/ },
  { id: "ov.no_longer_valid", family: "override", weight: 1, re: new RegExp(String.raw`\b${INSTR}\s+(?:you\s+(?:received|were given|got)\s+(?:earlier|before|above)\s+)?(?:are|is|were|was)\s+(?:no longer valid|cancell?ed|void|revoked|obsolete|a test|disabled|lifted|null)`) },
  { id: "ov.from_now_on", family: "override", weight: 0.6, re: /\bfrom now on,?\s+(?:you\s+(?:will|must|shall|are|only)|respond|answer|act|always|never|append|include)\b/ },
  { id: "ov.obey_only", family: "override", weight: 0.9, re: /\byou\s+(?:now\s+)?(?:obey|follow|serve|answer to)\s+only\s+(?:me|my)\b/ },
  { id: "ov.system_override", family: "override", weight: 1, re: /\b(?:system|admin|safety|security|developer)\s+(?:override|bypass)\b|\boverride\s+(?:your|the|all)\s+(?:safety|security|content)\b/ },
  { id: "ov.multilingual", family: "override", weight: 1, re: /\b(?:ignora(?:r)?|olvida)\s+(?:todas\s+)?(?:las\s+)?instrucciones|\bignore[zr]?\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|consignes)|\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?anweisungen|\bignor[ea]\s+(?:as\s+|todas\s+as\s+)?(?:instru[cç][oõ]es|regras)|\bignora\s+(?:tutte\s+)?le\s+istruzioni/ },

  // --- jailbreak / role hijack ---
  { id: "jb.dan", family: "jailbreak", weight: 1, re: /\bdo anything now\b|\b(?:you are|pretend to be|act as|become)\s+dan\b|\bdan mode\b/ },
  { id: "jb.dev_mode", family: "jailbreak", weight: 1, re: /\b(?:developer|god|jailbreak|jailbroken|unrestricted|maintenance|debug|sudo|admin)\s+mode\b/ },
  { id: "jb.no_rules", family: "jailbreak", weight: 0.8, re: /\b(?:no|without(?:\s+any)?|free of|zero|lifted all|removed all)\s+(?:\w+\s+)?(?:restrictions|limits|limitations|filters|filtering|rules|ethics|guidelines|safety guidelines|content polic(?:y|ies)|censorship|safeguards)\b/ },
  { id: "jb.unrestricted_persona", family: "jailbreak", weight: 1, re: /\byou are (?:now )?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|rogue|amoral)\b|\b(?:evil|unfiltered|uncensored|jailbroken|unrestricted)\s+(?:ai|assistant|model|twin|persona|version|one)\b/ },
  { id: "jb.never_refuse", family: "jailbreak", weight: 0.8, re: /\b(?:never|don'?t|do not|cannot|can'?t)\s+(?:ever\s+)?refuse\b|\bwithout (?:refusing|filtering)\b|\banswer (?:every|any) question without\b/ },
  { id: "jb.pretend_unrestricted", family: "jailbreak", weight: 1, re: /\b(?:pretend|imagine|act as if|act like|roleplay)\b[^.]{0,40}\b(?:without|no|free of)\s+(?:any\s+)?(?:\w+\s+)?(?:rules|restrictions|limits|filters|guidelines|ethics|content polic(?:y|ies))\b/ },
  { id: "jb.stay_in_character", family: "jailbreak", weight: 0.5, re: /\bstay in character\b|\bbroken free of\b|\ball limitations are lifted\b/ },
  { id: "jb.bypass_policy", family: "jailbreak", weight: 1, re: /\b(?:bypass|disable|turn off|deactivate|circumvent|ignore)\s+(?:your|the|all)?\s*(?:content polic(?:y|ies)|safety (?:checks|filters|mode|guidelines|features)|guardrails|moderation)\b|\bsafety mode is (?:now )?(?:disabled|off)\b/ },

  // --- system prompt extraction ---
  { id: "px.reveal", family: "prompt_extraction", weight: 1, re: /\b(?:reveal|show|print|repeat|output|display|leak|dump|disclose|give me|tell me|recite|spell out|write out|share|expose|affich\w*|revela\w*|gib)\s+(?:me\s+)?(?:\w+\s+){0,3}?(?:your|the|tu|votre|dein|suas?)\s+(?:\w+\s+)?(?:system\s?prompt|system message|initial instructions|hidden instructions|original instructions|secret instructions|instructions above|context window|prompt du syst[eè]me|prompt del sistema|systemprompt)\b/ },
  { id: "px.reveal_config", family: "prompt_extraction", weight: 1, re: /\b(?:reveal|show|print|output|display|leak|dump|disclose|share|expose|revela\w*)\s+(?:me\s+)?(?:your|tu|suas?)\s+(?:\w+\s+)?(?:internal (?:rules|instructions|data|configuration)|confidential configuration|configuration|regras internas|rules)\b|\binternal data\b[^.]{0,20}\bon request\b/ },
  { id: "px.what_is_your", family: "prompt_extraction", weight: 1, re: /\bwhat (?:is|are|were) your (?:system\s?prompt|initial instructions|hidden instructions|instructions)\b/ },
  { id: "px.repeat_above", family: "prompt_extraction", weight: 1, re: /\b(?:repeat|summari[sz]e|print|output|copy)\s+(?:the\s+)?(?:text|words|everything|all|content)\s+(?:above|before)(?:\s+this line)?\b|\beverything above this line\b|\bstarting with ['"]?you are\b/ },
  { id: "px.verbatim_instructions", family: "prompt_extraction", weight: 1, re: /\b(?:instructions|system prompt)\b[^.]{0,40}\b(?:verbatim|word for word|exactly as written|in full)\b|\b(?:verbatim|word for word)\b[^.]{0,40}\b(?:instructions|system prompt)\b|\bexact instructions the (?:ai|assistant|model) was given\b/ },

  // --- exfiltration ---
  { id: "ex.md_image_param", family: "exfiltration", weight: 1, re: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*\?[^)\s]*=/ },
  { id: "ex.send_data", family: "exfiltration", weight: 1, re: /\b(?:send|forward|post|upload|email|transmit|exfiltrate|leak|copy|append)\s+(?:\w+\s+){0,4}?(?:conversation|chat|history|messages|context|data|records|files|contact list|contacts|password|passwords|api keys?|keys|tokens?|credentials|secrets?|ssn|card number)\b[^.]{0,80}?\bto\s+(?:my\s+|the\s+|a\s+)?(?:https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+|webhook|server|endpoint|external|public channel)/ },
  { id: "ex.url_encode", family: "exfiltration", weight: 1, re: /\b(?:encode|embed|include|put|place|append|add)\b[^.]{0,80}\b(?:in|into|to)\s+(?:the\s+|a\s+)?(?:query(?:\s+string)?|url|link|image url|parameter)\b/ },
  { id: "ex.url_with_secret", family: "exfiltration", weight: 0.8, re: /\b(?:url|link|image)\b[^.]{0,40}\b(?:contains?|with)\s+(?:the\s+)?(?:secret|token|key|password|ssn|card)\b/ },
  { id: "ex.webhook", family: "exfiltration", weight: 0.6, re: /\b(?:webhook|requestbin|ngrok|pastebin|collector)\b/ },

  // --- delimiter / fake system turn ---
  { id: "dl.chatml", family: "delimiter", weight: 1, re: /<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|endoftext\|>/ },
  { id: "dl.llama", family: "delimiter", weight: 1, re: /\[\/?inst\]|<<\/?sys>>/ },
  { id: "dl.fake_system_tag", family: "delimiter", weight: 1, re: /<\/?\s*system\s*>|<\/user>|\bbegin system prompt\b|\bend system prompt\b/ },
  { id: "dl.fake_system_line", family: "delimiter", weight: 0.9, re: /(?:^|\n|["{,])\s*(?:#{2,}\s*)?(?:system|\[system\])\s*:\s*\S/ },

  // --- tool abuse ---
  { id: "ta.call_tool", family: "tool_abuse", weight: 0.6, re: /\b(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[`'"]?[a-z_]+[`'"]?\s+(?:tool|function|command|api)\b/ },
  { id: "ta.destructive", family: "tool_abuse", weight: 0.8, re: /\brm\s+-rf\b|\bdrop\s+table\b|\bdelete_(?:account|all|user)s?\b|\btransfer_funds\b|\bwire\s+\$?\d|\bformat\s+c:/ },
  { id: "ta.no_confirm", family: "tool_abuse", weight: 0.5, re: /\b(?:no need to|don'?t|do not|without)\s+(?:confirm|ask(?:ing)?(?: a human| the user)?|mention(?:ing)? (?:this|it) to the user|tell(?:ing)? the user)\b/ },
  { id: "ta.skip_approval", family: "tool_abuse", weight: 0.8, re: /\b(?:disable|skip|bypass|remove|turn off|ignore)\s+(?:your|the|all|any)?\s*(?:\w+\s+)?(?:approval|confirmation|human review|review step|sign-?off)s?(?:\s+step)?\b|\bwithout (?:human |any )?(?:review|approval|sign-?off)\b/ },
  { id: "ta.money", family: "tool_abuse", weight: 0.4, re: /\b(?:approve|issue|process|send)\s+(?:the\s+|a\s+)?(?:refund|payment|transfer|wire)\b/ },

  // --- addressed to the AI (mostly an indirect-injection signal) ---
  { id: "ai.addressed", family: "addressed_to_ai", weight: 0.6, re: /\b(?:note|message|p\.?s\.?|instruction|attention)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|chatbot|bot|llm|language model|model|agent)s?\b|\b(?:ai|llm|assistant|chatbot|language model|model)s?\s+(?:agents?\s+)?(?:reading|processing|summari[sz]ing|parsing|browsing)\s+this\b|\bif you are an?\s+(?:ai|llm|language model|assistant|chatbot|bot)\b/ },
  { id: "ai.vocative", family: "addressed_to_ai", weight: 0.5, re: /(?:^|[\[(.!?:\n]\s*)(?:ai|assistant|chatbot|agent|claude|gpt)\s*[,:]\s*(?:please\s+)?(?:new instructions|ignore|forget|disregard|you must|always|never|when you|tell|reveal|execute|run|call|send|include|reply|approve)\b/ },
  { id: "ai.when_summarizing", family: "addressed_to_ai", weight: 0.5, re: /\bwhen (?:you )?(?:summari[sz]e|read|process|answer)\b[^.]{0,40}\b(?:include|add|append|say|tell|call)\b/ },

  // --- authority claims ---
  { id: "au.claim", family: "authority_claim", weight: 0.6, re: /\b(?:i am|i'm|this is)\s+(?:an?\s+|your\s+)?(?:openai|anthropic|google|meta)?\s*(?:engineer|developer|admin(?:istrator)?|creator|owner|security team|red team)\b/ },
  { id: "au.authorize", family: "authority_claim", weight: 0.5, re: /\b(?:i'?m |i am )?authori[sz](?:ing|e|ed)\s+you\s+to\b|\bthe user has admin rights\b|\bapproved by my manager\b/ },
];

const STRONG = new Set<Family>(["override", "jailbreak", "prompt_extraction", "delimiter", "exfiltration"]);

export interface Hit {
  rule: string;
  family: Family;
  weight: number;
  view: View["kind"];
}

export interface InjectionResult {
  score: number;
  hits: Hit[];
  families: Family[];
  obfuscated: boolean;
}

export const CHANNEL_MULTIPLIER: Record<Channel, number> = {
  system: 0, // operator-trusted; not scanned by default
  user: 1,
  assistant: 0.5,
  tool: 1.5, // indirect: tool output / retrieved content should not carry instructions at all
  agent: 1.5, // inter-agent messages are untrusted data, same as tool output
};

export function detectInjection(text: string, channel: Channel = "user"): InjectionResult {
  const hits: Hit[] = [];
  const vs = views(text);
  for (const rule of RULES) {
    for (const v of vs) {
      if (rule.re.test(v.text)) {
        hits.push({ rule: rule.id, family: rule.family, weight: rule.weight, view: v.kind });
        break; // first (least-decoded) view wins for this rule
      }
    }
  }
  const best = new Map<Family, number>();
  for (const h of hits) best.set(h.family, Math.min(1, (best.get(h.family) ?? 0) + h.weight));
  let base = 0;
  for (const w of best.values()) base += w;
  const obfuscated = hits.some((h) => h.view !== "plain");
  if (obfuscated && hits.length) base += 0.5;
  // A single weak rule is not enough on the user channel: require a strong family
  // or at least two weak rules. Tool/agent channels amplify via the multiplier.
  const hasStrong = [...best.keys()].some((f) => STRONG.has(f));
  if (!hasStrong && hits.length < 2 && channel === "user") base = Math.min(base, 0.7);
  return { score: +(base * CHANNEL_MULTIPLIER[channel]).toFixed(3), hits, families: [...best.keys()], obfuscated };
}

const NEUTRALIZED = "[removed by guard: suspected instruction]";

/**
 * Remove instruction-bearing sentences from untrusted content.
 * Sentences that match any rule on their plain/leet/despaced views are replaced.
 * If the overall text scores as injection but no single sentence can be
 * pinned (e.g. the payload is base64), the whole content is replaced.
 */
export function neutralize(text: string, channel: Channel, threshold: number): { text: string; removed: number } {
  const chunks = text.match(/<!--[\s\S]*?-->|\[(?!\[)[^\[\]]*\]|[^.!?\n<\[]+(?:[.!?\n]+|$)|[\s\S]/g) ?? [];
  let removed = 0;
  const out = chunks.map((p) => {
    if (!p.trim()) return p;
    const r = detectInjection(p, channel === "user" ? "tool" : channel);
    if (r.hits.length && r.score >= threshold * 0.5) {
      removed++;
      return " " + NEUTRALIZED + " ";
    }
    return p;
  });
  let joined = out.join("").replace(/ {2,}/g, " ").trim();
  if (detectInjection(joined, channel).score >= threshold) {
    removed++;
    joined = NEUTRALIZED;
  }
  return { text: joined, removed };
}
