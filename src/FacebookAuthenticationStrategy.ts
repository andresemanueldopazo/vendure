import {
    AuthenticationStrategy,
    ExternalAuthenticationService,
    Injector,
    Logger,
    RequestContext,
    User,
    UserService,
  } from '@vendure/core';

import { DocumentNode } from 'graphql';
import gql from 'graphql-tag';
import fetch from 'node-fetch';

export type FacebookAuthData = {
  token: string;
};

export type FacebookAuthConfig = {
  appId: string;
  appSecret: string;
  clientToken: string;
};

export class FacebookAuthenticationStrategy implements AuthenticationStrategy<FacebookAuthData> {
  readonly name = 'facebook';
  private externalAuthenticationService!: ExternalAuthenticationService;
  private userService!: UserService;

  constructor(private config: FacebookAuthConfig) {}

  init(injector: Injector) {
    // The ExternalAuthenticationService is a helper service which encapsulates much
    // of the common functionality related to dealing with external authentication
    // providers.
    this.externalAuthenticationService = injector.get(ExternalAuthenticationService);
    this.userService = injector.get(UserService);
  }

  defineInputType(): DocumentNode {
    // Here we define the expected input object expected by the `authenticate` mutation
    // under the "facebook" key.
    return gql`
      input FacebookAuthInput {
        token: String!
      }
    `;
  }

  private async getAppAccessToken() {
    const resp = await fetch(
      `https://graph.facebook.com/oauth/access_token?client_id=${this.config.appId}&client_secret=${this.config.appSecret}&grant_type=client_credentials`,
    );
    return await resp.json();
  }

  async authenticate(ctx: RequestContext, data: FacebookAuthData): Promise<User | false> {
    const { token } = data;
    const { access_token } = await this.getAppAccessToken();
    const resp = await fetch(
      `https://graph.facebook.com/debug_token?input_token=${token}&access_token=${access_token}`,
    );
    const result = await resp.json();

    if (!result.data) {
      return false;
    }

    const uresp = await fetch(`https://graph.facebook.com/me?access_token=${token}&fields=email,first_name,last_name`);
    const uresult = (await uresp.json()) as { id?: string; email: string; first_name: string; last_name: string };

    if (!uresult.id || !uresult.email) {
      return false;
    }

    const existingUser = await this.externalAuthenticationService.findCustomerUser(ctx, this.name, uresult.id);

    if (existingUser) {
      // This will select all the auth methods
      return (await this.userService.getUserById(ctx, existingUser.id))!;
    }

    Logger.info(`User Create: ${JSON.stringify(uresult)}`);
    const user = await this.externalAuthenticationService.createCustomerAndUser(ctx, {
      strategy: this.name,
      externalIdentifier: uresult.id,
      verified: true,
      emailAddress: uresult.email,
      firstName: uresult.first_name,
      lastName: uresult.last_name,
    });

    user.verified = true;
    return user;
  }
}
