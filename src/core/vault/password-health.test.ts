import { describe, it, expect } from 'vitest';
import { scorePasswordStrength, isWeakPassword, buildPasswordHealthReport } from './password-health.js';

describe('scorePasswordStrength', () => {
  it('scores common and trivial passwords as 0', () => {
    expect(scorePasswordStrength('password')).toBe(0);
    expect(scorePasswordStrength('123456')).toBe(0);
    expect(scorePasswordStrength('aaaaaaaa')).toBe(0);
    expect(scorePasswordStrength('')).toBe(0);
  });

  it('caps short passwords as weak even with high variety', () => {
    expect(scorePasswordStrength('aA1!')).toBeLessThanOrEqual(1);
  });

  it('scores long, varied passwords as strong', () => {
    expect(scorePasswordStrength('Tr0ub4dour&3xplore!')).toBeGreaterThanOrEqual(3);
  });
});

describe('isWeakPassword', () => {
  it('flags weak passwords and not strong ones', () => {
    expect(isWeakPassword('password')).toBe(true);
    expect(isWeakPassword('short1')).toBe(true);
    expect(isWeakPassword('Tr0ub4dour&3xplore!')).toBe(false);
  });
});

describe('buildPasswordHealthReport', () => {
  it('flags reused passwords with their reuse count and weakness', () => {
    const report = buildPasswordHealthReport([
      { id: '1', name: 'A', password: 'reused1!XYZ' },
      { id: '2', name: 'B', password: 'reused1!XYZ' },
      { id: '3', name: 'C', password: 'Str0ng&Unique!pass' },
      { id: '4', name: 'D', password: 'password' },
    ]);
    const byId = new Map(report.map((e) => [e.id, e]));
    expect(byId.get('1')).toMatchObject({ reuseCount: 2 });
    expect(byId.get('2')).toMatchObject({ reuseCount: 2 });
    expect(byId.get('3')).toMatchObject({ reuseCount: 1, weak: false });
    expect(byId.get('4')).toMatchObject({ weak: true });
  });

  it('ignores logins without a password', () => {
    const report = buildPasswordHealthReport([{ id: '1', name: 'A' }]);
    expect(report).toEqual([]);
  });
});
