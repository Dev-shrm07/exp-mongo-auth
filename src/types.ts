export interface Config {
    jwtSecret: string;
    mongoUrl: string;
    emailService: {
      email: string;
      password: string;
    };
    frontendUrl: string;
    validDomains: Map<string, string>;


}



