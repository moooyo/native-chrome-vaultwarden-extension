export function isIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (year < 1 || year > 9_999 || month < 1 || month > 12
    || day < 1 || day > daysInMonth(year, month)
    || hour > 23 || minute > 59 || second > 59) return false;

  const offsetHour = match[10] === undefined ? 0 : Number(match[10]);
  const offsetMinute = match[11] === undefined ? 0 : Number(match[11]);
  if (offsetHour > 14 || offsetMinute > 59 || (offsetHour === 14 && offsetMinute !== 0)) return false;
  const offsetSign = match[9] === '-' ? -1 : 1;
  const offsetMinutes = match[8] === 'Z' ? 0 : offsetSign * (offsetHour * 60 + offsetMinute);
  const ticksPerSecond = 10_000_000n;
  const fraction = BigInt((match[7] ?? '').padEnd(7, '0'));
  const instant = BigInt(daysFromCivil(year, month, day)) * 86_400n * ticksPerSecond
    + BigInt(hour * 3_600 + minute * 60 + second) * ticksPerSecond
    + fraction
    - BigInt(offsetMinutes * 60) * ticksPerSecond;
  const minimum = BigInt(daysFromCivil(1, 1, 1)) * 86_400n * ticksPerSecond;
  const maximum = BigInt(daysFromCivil(9_999, 12, 31)) * 86_400n * ticksPerSecond
    + 86_399n * ticksPerSecond
    + 9_999_999n;
  return instant >= minimum && instant <= maximum;
}

export function isOptionalNullableIsoTimestamp(
  value: unknown,
): value is string | null | undefined {
  return value === undefined || value === null || isIsoTimestamp(value);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysFromCivil(year: number, month: number, day: number): number {
  const adjustedYear = year - (month <= 2 ? 1 : 0);
  const era = Math.floor(adjustedYear / 400);
  const yearOfEra = adjustedYear - era * 400;
  const shiftedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear = Math.floor((153 * shiftedMonth + 2) / 5) + day - 1;
  const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4)
    - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}
