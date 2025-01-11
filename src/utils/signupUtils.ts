
import { uniqueNamesGenerator, Config as uniqueconfig, adjectives, animals, colors, countries, names, starWars, NumberDictionary } from "unique-names-generator";
import UserModel from "../models/User"
import { Config  as configtype } from "../types"
import { getConfig } from "../init"





export async function generateUniqueUsername(): Promise<string> {
    const allDictionaries = [adjectives, animals, colors, countries, names, starWars];
    const maxRetries = 4; 
    let retries = 0;
    const config:configtype = getConfig()

  
    while (retries < maxRetries) {
      const selectedDictionaries: any[] = [];
      while (selectedDictionaries.length < 3) {
        const randomDict = allDictionaries[Math.floor(Math.random() * allDictionaries.length)];
        if (!selectedDictionaries.includes(randomDict)) {
          selectedDictionaries.push(randomDict);
        }
      }
      const seperators:string[] = ['-','_','']
      const config: uniqueconfig = {
        dictionaries: selectedDictionaries,
        separator: seperators[Math.floor(Math.random() * seperators.length)],
        length: 3,
      };
      const newUsername = uniqueNamesGenerator(config);

      const existingUser = await UserModel.findOne({ username: newUsername }).select('username');
      if (!existingUser) {
        return newUsername; 
      }
  
      retries++;
    }

    const fallbackUsername = uniqueNamesGenerator({
      dictionaries: [adjectives, animals, colors],
      separator: '_',
      length: 3,
    });
    const randomNumber = Math.floor(Math.random() * 10000); 
    return `${fallbackUsername}_${randomNumber}`;
}






export const checkValidEmail= (email:string):boolean=>{
    const config:configtype = getConfig()
    const valid_email_domains:Map<string,string> = config.validDomains

    const match = email.match(/@([\w.-]+)$/);
    if (!match){
        return false
    }
    const domain = match[1]
    if (valid_email_domains.has(domain)){
        return true
    }
    return false
}



export const getAff= (email:string):string|null=>{
    const config:configtype = getConfig()
    const valid_email_domains:Map<string,string> = config.validDomains
    const match = email.match(/@([\w.-]+)$/);
    if (!match){
        return null
    }
    const domain = match[1]
    if (valid_email_domains.has(domain)){
        return valid_email_domains.get(domain)!
    }
    return null
}


