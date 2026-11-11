// store.js — key persistence. SecureStore (hardware keystore) where
// available, AsyncStorage fallback. WIF is stored — never uploaded.
import AsyncStorage from "@react-native-async-storage/async-storage";

let SecureStore = null;
try { SecureStore = require("expo-secure-store"); } catch (e) { /* fallback */ }

export async function saveWif(wif) {
  if (SecureStore) await SecureStore.setItemAsync("alpha_wif", wif);
  else await AsyncStorage.setItem("alpha_wif", wif);
}
export async function loadWif() {
  if (SecureStore) return await SecureStore.getItemAsync("alpha_wif");
  return await AsyncStorage.getItem("alpha_wif");
}
export async function clearWif() {
  if (SecureStore) await SecureStore.deleteItemAsync("alpha_wif");
  else await AsyncStorage.removeItem("alpha_wif");
}
