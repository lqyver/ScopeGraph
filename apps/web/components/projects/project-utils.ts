export function projectDeleteConfirmationMatches(projectName: string, confirmation: string) {
  return confirmation === projectName;
}
