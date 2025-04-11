export const useAuth = () => {
  const session = useSession();

  return {
    user: session.value ? session.value.user : null,
    isAuthenticated: !!session.value?.user,
  };
};
