import type { LinkedFieldSource } from '../../core/vault/linked-fields.js';
import { t } from '../i18n/index.js';

export function linkedFieldSourceLabel(source: LinkedFieldSource): string {
  switch (source) {
    case 'username': return t('detail.username');
    case 'password': return t('detail.password');
    case 'cardholderName': return t('detail.cardholder');
    case 'number': return t('detail.cardNumber');
    case 'brand': return t('editor.linkedBrand');
    case 'expMonth': return t('editor.linkedExpirationMonth');
    case 'expYear': return t('editor.linkedExpirationYear');
    case 'code': return t('detail.cardCode');
    case 'title': return t('detail.identityTitle');
    case 'firstName': return t('detail.firstName');
    case 'middleName': return t('detail.middleName');
    case 'fullName': return t('editor.linkedFullName');
    case 'lastName': return t('detail.lastName');
    case 'company': return t('detail.company');
    case 'email': return t('detail.email');
    case 'phone': return t('detail.phone');
    case 'address1': return t('detail.address1');
    case 'address2': return t('detail.address2');
    case 'address3': return t('detail.address3');
    case 'city': return t('detail.city');
    case 'state': return t('detail.state');
    case 'postalCode': return t('detail.postalCode');
    case 'country': return t('detail.country');
    case 'ssn': return t('detail.ssn');
    case 'passportNumber': return t('detail.passportNumber');
    case 'licenseNumber': return t('detail.licenseNumber');
  }
}
