// Built-in passphrase wordlist: common, distinct, memorable English words (lowercase, ASCII).
// Entropy is log2(list length) per word (~8 bits here); raising the word count or swapping in the full
// EFF large wordlist (7776 words ≈ 12.9 bits/word) increases strength. A test enforces uniqueness/format.

export const PASSPHRASE_WORDLIST: readonly string[] = [
  'able', 'acid', 'acorn', 'actor', 'adapt', 'agent', 'album', 'alert', 'alien', 'alley', 'alpha', 'amber', 'angel', 'anger', 'ankle', 'apple',
  'april', 'apron', 'arena', 'armor', 'arrow', 'asset', 'atlas', 'audio', 'audit', 'autumn', 'awake', 'award', 'badge', 'baker', 'banjo', 'basil',
  'basin', 'batch', 'beach', 'beans', 'beard', 'beast', 'bench', 'berry', 'bingo', 'birch', 'blade', 'blaze', 'blend', 'blink', 'block', 'bloom',
  'board', 'bonus', 'boost', 'booth', 'brain', 'brave', 'bread', 'brick', 'brief', 'broom', 'brush', 'bunny', 'cabin', 'cable', 'camel', 'candy',
  'canoe', 'canon', 'cargo', 'carol', 'carry', 'cedar', 'chain', 'chalk', 'charm', 'chart', 'chase', 'cheek', 'chess', 'chief', 'chime', 'chord',
  'civic', 'claim', 'clamp', 'clash', 'clean', 'clerk', 'cliff', 'climb', 'cloak', 'clock', 'cloud', 'clove', 'clown', 'coach', 'coast', 'cobra',
  'cocoa', 'comet', 'coral', 'couch', 'cover', 'crane', 'crate', 'cream', 'creek', 'crest', 'crisp', 'crown', 'crumb', 'curve', 'daisy', 'dance',
  'decay', 'delta', 'depot', 'diary', 'diner', 'ditch', 'diver', 'dough', 'dozen', 'draft', 'drama', 'dream', 'dress', 'drift', 'drink', 'drive',
  'drone', 'eagle', 'early', 'earth', 'easel', 'ebony', 'elbow', 'elder', 'ember', 'empty', 'enjoy', 'entry', 'equal', 'ethic', 'event', 'exile',
  'extra', 'fable', 'fancy', 'feast', 'fence', 'ferry', 'fever', 'fiber', 'field', 'fight', 'final', 'finch', 'flame', 'flask', 'fleet', 'flint',
  'float', 'flock', 'flora', 'flour', 'fluid', 'flute', 'focus', 'foggy', 'forge', 'forty', 'found', 'frame', 'fresh', 'frost', 'fruit', 'fudge',
  'gauge', 'ghost', 'giant', 'glass', 'gleam', 'globe', 'glove', 'grace', 'grain', 'grape', 'grass', 'green', 'grill', 'groom', 'group', 'grove',
  'guard', 'guest', 'guide', 'habit', 'happy', 'hardy', 'hazel', 'heart', 'hedge', 'hello', 'heron', 'hippo', 'hobby', 'honey', 'horse', 'hotel',
  'house', 'hover', 'human', 'humor', 'ideal', 'image', 'index', 'ivory', 'jelly', 'jewel', 'joint', 'jolly', 'judge', 'juice', 'kayak', 'kiosk',
  'knife', 'koala', 'label', 'lemon', 'lever', 'light', 'lilac', 'linen', 'llama', 'lobby', 'local', 'lodge', 'logic', 'lotus', 'lucky', 'lunar',
  'lunch', 'magic', 'mango', 'maple', 'march', 'marsh', 'medal', 'melon', 'mercy', 'metal', 'meter', 'model', 'motor', 'mound', 'mouse', 'mover',
];
