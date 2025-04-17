import { TransactionData, AbstractTransactionStore } from '@auth0/auth0-web-js';
import Cookies from 'js-cookie';

export class CookieTransactionStore extends AbstractTransactionStore {
  async set(
    identifier: string,
    transactionData: TransactionData,
  ): Promise<void> {
    const inOneHour = new Date(new Date().getTime() + 60 * 60 * 1000);

    Cookies.set(
      identifier,
      JSON.stringify(transactionData),
      {
        expires: inOneHour,
      }
    )
  }

  async get(identifier: string): Promise<TransactionData | undefined> {
    const data = Cookies.get(identifier);

    if (data){
      return JSON.parse(data);
    }

    return undefined;
  }

  async delete(identifier: string): Promise<void> {
    Cookies.remove(identifier);
  }
}